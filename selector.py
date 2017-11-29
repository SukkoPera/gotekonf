#!/usr/bin/env python

import os
import struct
import subprocess
import re
import stat
import fnmatch

# TEMP
import hashlib

from collections import namedtuple

Stats = namedtuple ('Stats', ['nImages', 'defaultSlot'])

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

def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines)

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
	@staticmethod
	def getFileAtCluster (dev, mountp, clu):
		rx = r"Found\s+(.+)\s+in\s+directory\s+(.+)\s+\(.+\)"

		exe = findInPath ("fatcat")
		cmd = [exe, dev, "-k", str (clu)]
		#~ print "Running: %s" % str (cmd)
		output = subprocess.check_output(cmd)
		#~ print "Output is: %s" % output
		rc = re.compile (rx)

		ret = None
		for line in output.split ('\n'):
			match = rc.match (line)
			if match is not None:
				#~ print "OK %s" % str(match.groups ())
				filename = match.group (1)
				dir_ = match.group (2)

				if filename[0] == "/":
					filename = filename[1:]
				path = os.path.join (mountp, filename)
				#~ print "Trying %s" % path
				if os.path.exists (path):
					ret = filename
					break
				else:
					#~ print "Found %s but does not exist" % path
					pass

		return ret

	@staticmethod
	def getStartingCluster (dev, path):
		"""path must be relative to device root"""
		rx = r"f\s+(\S+)\s+(\S+)\s+(.+?)\s+c=(\d+)\s+s=(\d+)\s+\(\S+\)"

		dn = os.path.dirname (path)
		bn = os.path.basename (path)
		cmd = ["fatcat", dev, "-l", dn]
		#~ print "Running: %s" % str (cmd)
		output = subprocess.check_output(cmd)
		#~ print "Output is: %s" % output
		rc = re.compile (rx)

		ret = None
		for line in output.split ('\n'):
			match = rc.match (line)
			if match is not None:
				#~ print "OK %s" % str(match.groups ())
				date_ = match.group (1)
				time_ = match.group (2)
				filename = match.group (3)
				cluster = int (match.group (4))
				size = match.group (5)

				if filename == bn:
					ret = cluster
					break

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
		self.mntp = _mntp

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

		print "Stat bytes:"
		print "DEC:\t%d\t%d\t%d\t%d" % (unk1, unk2, unk3, unk4)
		print "HEX:\t%02x\t%02x\t%02x\t%02x" % (unk1, unk2, unk3, unk4)
		print

		return Stats (nImages, defaultSlot)

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
				#~ if i == 3:
					#~ print hexdump (buf)
					#~ print hashlib.sha1 (buf).hexdigest ()

				data = struct.unpack ("< 11s 2B 2I 41s 66B", buf)
				shortName = data[0].rstrip ('\0')
				unk1 = data[1]
				unk2 = data[2]
				startCluster = data[3]
				fileSize = data[4]
				fileName = data [5].rstrip ('\0')
				zeros = data [6:]
				print shortName, startCluster

				# Some sanity checks, for what we understood the format
				assert unk1 == 0
				assert unk2 == 0
				assert all ([x == 0 for x in zeros])

				# Try to come up with actual file corresponding to cluster
				# Will be None if not found
				fn = Fat32Filesystem.getFileAtCluster (self.dev, self.mntp, startCluster)

				s = Slot (i, False, shortName, startCluster, fileSize, fileName, fn)
				slots[i] = s

		return slots

	def scan (self):
		with open (self.adf, "rb") as fp:
			self.defaultSlot = self._getStats (fp).defaultSlot
			self.slots = self._getSlots (fp)
			print "Slots in use: %d" % len (self.slots)
			print "Default slot: %d" % self.defaultSlot

	def setDefaultSlot (self, slotNo):
		if slotNo in self.slots:
			with open (self.adf, "rb+") as fp:
				fp.seek (Selector.STATS_OFFSET + 2)
				s = struct.pack ("< B", slotNo)
				fp.write (s)
		else:
			raise SelectorException ("Cannot set an empty slot as default")

	def updateSlot (self, slot):
		if slot.cleared:
			buf = struct.pack ("< 128B", *([0] * Selector.REC_SIZE))
		else:
			# struct.pack() will take care of padding and or shortening long/short strings
			buf = struct.pack (Selector._SLOT_STRUCT, slot.shortName, 0, 0, slot.startCluster, slot.fileSize, slot.fileName, *([0] * 66))
		offset = self._getSlotOffset (slot.num)
		#~ print hexdump (buf)
		#~ print hashlib.sha1 (buf).hexdigest ()
		with open (self.adf, "rb+") as fp:
			fp.seek (offset)
			fp.write (buf)
		self.slots[slot.num] = slot

	# Call this with a DICT of slots
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
			print "File for slot %d is missing: %s" % (n, slot.fileName)

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

def remap (dev, mntp):
	adfs = findFiles ("*.adf", mntp)
	adfs = filter (lambda f: os.path.basename (f).lower () != "selector.adf", adfs)
	print "Found %d ADF files" % len (adfs)

	slots = {}
	for n, adf in enumerate (adfs, start = 1):
		print "%2d. %s" % (n, adf)
		relpath = os.path.relpath (adf, mntp)
		bn = os.path.basename (adf)
		sz = os.path.getsize (adf)
		clu = Fat32Filesystem.getStartingCluster (dev, relpath)
		assert clu is not None
		slot = Slot (n, False, bn, clu, sz, bn, adf)
		#~ print slot
		slots[n] = slot

	for n in range (len (adfs) + 1, Selector.MAX_SLOTS):
		slot = Slot (n, True, "", 0x00, 0, "", "")
		slots[n] = slot

	return slots

if __name__ == "__main__":
	dev, mntp = ("/dev/sdc1", "/run/media/sukko/GOTEK")
	s = Selector (dev, mntp)
	s.scan ()

	for n, slot in s.slots.iteritems ():
		print "%2d. %s" % (n, slot.diskFileName)

	nProb = checkSlots ("/run/media/sukko/GOTEK", s.slots)
	#~ if nProb == 0:
		#~ print "Selector is safe and sound!"
	#~ else:
		#~ for slot in s.slots.itervalues ():
			#~ s.updateSlot (slot)

	#~ s.setDefaultSlot (3)
	#~ s.updateSlot (s.slots[3])

	#~ slots = remap (dev, mntp)
	#~ s.updateSlots (slots)
