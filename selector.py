#!/usr/bin/env python

import sys
import os
import struct
import subprocess
import re
import stat
import fnmatch
import argparse

from collections import namedtuple

from fat import FAT

Stats = namedtuple ('Stats', ['nImages', 'defaultSlot', 'unk1', 'unk2', 'unk3', 'unk4'])

# cleared is True if slot should be cleared
# diskFileName is actual path relative to device root (or None if not found),
# all other fields come from the record
class Slot (object):
	def __init__ (self, _num, _cleared, _shortName, _startCluster, _fileSize, _fileName, _diskFileName):
		self.num = _num
		self.cleared = _cleared
		self.shortName = _shortName
		self.startCluster = _startCluster
		self.fileSize = _fileSize
		self.fileName = _fileName
		self.diskFileName = _diskFileName

class NotFoundInPathException (Exception):
	def __init__ (self, exe):
		self.exe = exe

	def __str__ (self):
		return "Executable not found in path: %s" % self.exe

def findInPath (exe):
	"""Find the file named exe in the system path.
	Returns the full path name if found, throws if not found"""

	for dirname in os.environ['PATH'].split (os.path.pathsep):
		possible = os.path.join (dirname, exe)
		if os.path.isfile (possible):
			return possible

	# Not found
	raise NotFoundInPathException (exe)

class Fat32Filesystem (object):
	def __init__ (self, device, mountpoint):
		self.device = device
		self.mountpoint = mountpoint
		self.fat = FAT (open (device, "rb"))
		self.files = self.get_all_files ()
		#~ for f in self.files:
			#~ print f["name"], f["cluster"]

	def get_all_files (self, path="", skipDots = True):
		files = self.fat.read_dir (path)
		files2 = []
		for f in files:
			if f["name"] != "." and f["name"] != "..":
				if len (path):
					f["name"] = path + "/" + f["name"]
				if f["attributes"] & FAT.Attribute.DIRECTORY:
					#~ print "Recursing into '%s' - '%s'" % (f["name"], path)
					files2.extend (self.get_all_files (f["name"]))
				files2.append (f)
			elif not skipDots:
				files2.append (f)
		return files2

	def getFileAtCluster (self, clu):
		fn = filter (lambda f: f["cluster"] == clu, self.files)
		if len (fn) == 1:
			ret = fn[0]["name"]
		else:
			ret = None
		return ret

	def getStartingCluster (self, path):
		"""path must be relative to device root"""
		fn = filter (lambda f: f["name"] == path, self.files)
		if len (fn) == 1:
			ret = fn[0]["cluster"]
		else:
			ret = None
		return ret

class SelectorException (BaseException):
	pass

class Selector (object):
	STATS_OFFSET = 0x29416
	STATS_SIZE = 8
	REC_OFFSET = 0x29880
	REC_SIZE = 128
	MAX_SLOTS = 999

	_SLOT_STRUCT = "< 11s 2B 2I 41s 66B"

	def __init__ (self, _dev, _mntp):
		self.dev = _dev
		self.mountpoint = _mntp
		self.fs = Fat32Filesystem (_dev, _mntp)

		self.adf = os.path.join (_mntp, "selector.adf")
		if not os.path.isfile (self.adf):
			raise SelectorException ("selector.adf not found")

	def _getStats (self, fp):
		fp.seek (Selector.STATS_OFFSET)
		buf = fp.read (Selector.STATS_SIZE)
		data = struct.unpack ("2H 4B", buf)
		nImages = data[0]
		defaultSlot = data[1]
		unk1 = data[2]	# Went E5, F5...
		unk2 = data[3]	# Always 01?
		unk3 = data[4]
		unk4 = data[5]
		return Stats (nImages, defaultSlot, unk1, unk2, unk3, unk4)

	def _getSlotOffset (self, n):
		return Selector.REC_OFFSET + (n - 1) * Selector.REC_SIZE

	# Read records
	def _getSlots (self, fp):
		slots = {}

		fp.seek (Selector.REC_OFFSET)
		for i in range (1, Selector.MAX_SLOTS + 1):
			#~ print fp.tell ()
			assert self._getSlotOffset (i) == fp.tell ()
			buf = fp.read (Selector.REC_SIZE)
			if not buf:
				raise SelectorException ("Read from selector.adf failed")

			if buf[0] != '\0':
				data = struct.unpack ("< 11s 2B 2I 41s 66B", buf)
				shortName = data[0].rstrip ('\0')
				unk1 = data[1]
				unk2 = data[2]
				startCluster = data[3]
				fileSize = data[4]
				fileName = data [5].rstrip ('\0')
				zeros = data [6:]

				# Some sanity checks, for what we understood the format
				assert unk1 == 0
				assert unk2 == 0
				assert all ([x == 0 for x in zeros])

				# Try to come up with actual file corresponding to cluster
				# Will be None if not found
				fn = self.fs.getFileAtCluster (startCluster)

				s = Slot (i, False, shortName, startCluster, fileSize, fileName, fn)
				slots[i] = s

		return slots

	def scan (self):
		with open (self.adf, "rb") as fp:
			self.stats = self._getStats (fp)
			self.defaultSlot = self.stats.defaultSlot
			self.slots = self._getSlots (fp)

	def setDefaultSlot (self, slotNo):
		if slotNo in self.slots:
			with open (self.adf, "rb+") as fp:
				fp.seek (Selector.STATS_OFFSET + 2)
				s = struct.pack ("< B", slotNo)
				fp.write (s)
		else:
			raise SelectorException ("Cannot set an empty slot as default")

	# Updates slot cluster according to slot filename
	def mapSlot (self, slot):
		ret = False
		if slot.diskFileName is not None and len (slot.diskFileName) > 0:
			clu = self.fs.getStartingCluster (slot.diskFileName)
			if clu is not None:
				slot.startCluster = clu
				ret = True
		return ret

	# Call this with a DICT (slot# -> slot)
	def updateSlots (self, slots):
		with open (self.adf, "rb+") as fp:
			fp.seek (Selector.REC_OFFSET)
			for i in range (1, Selector.MAX_SLOTS + 1):
				assert self._getSlotOffset (i) == fp.tell ()
				if i in slots:
					slot = slots[i]
					if slot.cleared:
						buf = struct.pack ("< 128B", *([0] * Selector.REC_SIZE))
					else:
						# struct.pack() will take care of padding and or shortening long/short strings
						buf = struct.pack (Selector._SLOT_STRUCT, slot.shortName, 0, 0, slot.startCluster, slot.fileSize, slot.fileName, *([0] * 66))
					fp.write (buf)

def findFile (fn, root):
	ret = []
	for f in os.listdir (root):
		fullf = os.path.join (root, f)
		if os.path.isdir (fullf):
			ret.extend (findFile (fn, fullf))
		elif os.path.isfile (fullf) and f == fn:
			#~ print "Found: %s" % fullf
			ret.append (fullf)
	return sorted (ret)

def checkSlots (mntp, slots, fix = True):
	nProb = 0
	for n, slot in s.slots.iteritems ():
		if slot.diskFileName is None:
			# No file found at cluster, see if filename still exists. Note that
			# this will most likely fail, as slot.filename might not contain a
			# full filename. Also the path is lost.
			candidates = findFile (slot.fileName, mntp)
			candidates = map (lambda f: f[len (mntp) + 1:], candidates)
			print "File for slot %d is missing: %s (c=%u)" % (n, slot.fileName, slot.startCluster)

			# FIXME
			if True or len (candidates) == 0:
				print "No candidates found, clearing slot"
				if fix:
					slot.cleared = True
			elif len (candidates) == 1:
				print "Found %s, updating record"
				# FIXME
			else:
				print "Found several candidates:"
				for n, c in enumerate (candidates, start = 1):
					print "%2d. %s" % (n, c)
					# FIXME
			#~ print slot
			nProb += 1
		else:
			fullpath = os.path.join (mntp, slot.diskFileName)
			assert os.path.isfile (fullpath)
			st = os.stat (fullpath)
			#~ print st
			#~ print slot.startCluster
			sz = os.path.getsize (fullpath)
			if sz != slot.fileSize:
				print "Slot %d has wrong filesize" % n
				if fix:
					slot.fileSize = sz
				nProb += 1
	return nProb

def findFiles (pattern, root):
	ret = []
	recurse = []
	for f in os.listdir (root):
		fullf = os.path.join (root, f)
		if os.path.isdir (fullf):
			recurse.append (fullf)
		elif os.path.isfile (fullf) and fnmatch.fnmatch (f.lower (), pattern):
			#~ print "Found: %s" % fullf
			ret.append (fullf)
	for d in sorted (recurse):
		ret.extend (findFiles (pattern, d))
	return ret

def remap (sel, verbose = False):
	adfs = findFiles ("*.adf", sel.mountpoint)
	adfs = filter (lambda f: os.path.basename (f).lower () != "selector.adf", adfs)
	print "Found %d ADF files:" % len (adfs)

	slots = {}
	for n, adf in enumerate (adfs, start = 1):
		relpath = os.path.relpath (adf, sel.mountpoint)
		print "%2d. %s" % (n, relpath)
		bn = os.path.basename (adf)
		sz = os.path.getsize (adf)
		slot = Slot (n, False, bn, 0x00, sz, bn, relpath)
		mapped = sel.mapSlot (slot)
		assert mapped, "Cannot find cluster for file '%s'" % adf
		if verbose:
			print "- Mapped to cluster %u" % slot.startCluster
		slots[n] = slot

	for n in range (len (adfs) + 1, Selector.MAX_SLOTS + 1):
		slot = Slot (n, True, "", 0x00, 0, "", "")
		slots[n] = slot

	# Commit
	assert len (slots) == Selector.MAX_SLOTS, len (slots)
	s.updateSlots (slots)


# Thanks tzot ;)
# https://stackoverflow.com/questions/4260116/find-size-and-free-space-of-the-filesystem-containing-a-given-file#12327880
def get_mounted_device(pathname):
	"Get the device mounted at pathname"
	# uses "/proc/mounts"
	if pathname.endswith ("/"):
		pathname = pathname[:-1]
	pathname= os.path.normcase(pathname) # might be unnecessary here
	try:
		with open("/proc/mounts", "r") as ifp:
			for line in ifp:
				fields= line.rstrip('\n').split()
				# note that line above assumes that
				# no mount points contain whitespace
				if fields[1] == pathname:
					return fields[0]
	except EnvironmentError:
		pass
	return None # explicit

parser = argparse.ArgumentParser (description = 'Manage disk images for Amiga Gotek drives')
parser.add_argument ('--list', "-l", action = 'store_true', default = False, help = "List disk images")
parser.add_argument ('--check', "-c", action = 'store_true', default = False, help = "Check disk images")
parser.add_argument ('--remap', "-r", action = 'store_true', default = False, help = "Remap all disk images to slots")
parser.add_argument ('--set-default', "-d", metavar = "IMAGE_NO", default = None, dest = "defaultImage",
										 help = "Number of image to set as default")
parser.add_argument ('--verbose', "-v", action = 'store_true', default = False, help = "Be verbose")
parser.add_argument ('path', default = None, type = str, help = 'USB Drive Mountpoint')

args = parser.parse_args ()

# This is ensured by argparse
assert args.path is not None

# Only accept one mode argument
l = [args.list, args.check, args.remap, args.defaultImage]
f = filter (lambda x: bool (x), l)
if len (f) == 0:
	print "No operation mode specified"
	parser.print_help ()
	sys.exit (10)
elif len (f) > 1:
	print "Please specify a single operation mode"
	parser.print_help ()
	sys.exit (10)

# Find out device for mountpoint
dev = get_mounted_device (args.path)
if dev is None:
	print "ERROR: Cannot find device mounted on %s" % args.path
	sys.exit (20)

print "Using %s, mounted on %s" % (dev, args.path)

# Go!
s = Selector (dev, args.path)
s.scan ()
print "Slots in use: %d" % len (s.slots)
print "Default slot: %d" % s.defaultSlot
print

if args.verbose:
	print "Stat bytes:"
	print "DEC:\t%d\t%d\t%d\t%d" % (s.stats.unk1, s.stats.unk2, s.stats.unk3, s.stats.unk4)
	print "HEX:\t%02x\t%02x\t%02x\t%02x" % (s.stats.unk1, s.stats.unk2, s.stats.unk3, s.stats.unk4)
	print

if args.list:
	for n, slot in s.slots.iteritems ():
		if args.verbose:
			print "%2d. %s (c=%u)" % (n, slot.diskFileName, slot.cluster)
		else:
			print "%2d. %s" % (n, slot.diskFileName)
elif args.check:
	nProb = checkSlots (args.path, s.slots)
	if nProb == 0:
		print "Selector is safe and sound!"
	#~ else:
		#~ for slot in s.slots.itervalues ():
			#~ s.updateSlot (slot)
elif args.remap:
	remap (s, args.verbose)
elif args.defaultImage:
	n = int (args.defaultImage)
	s.setDefaultSlot (n)
	print "Default image set to %d" % n
	#~ s.updateSlot (s.slots[3])

