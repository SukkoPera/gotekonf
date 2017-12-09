#!/usr/bin/env python

# Derived from pyfat: https://github.com/jonasgulle/pyfat

from datetime import datetime, date
from struct import unpack
from os import SEEK_SET
import logging

# https://www.pjrc.com/tech/8051/ide/fat32.html
# https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system#VFAT

class FAT(object):
	Version = "0.01"

	# Static constants used
	EOF_FAT12 = 0x00000ff8
	EOF_FAT16 = 0x0000fff8
	EOF_FAT32 = 0x0ffffff8
	# The size of a FAT directory entry
	DIRSIZE = 32

	class Type:
		FAT12 = 1
		FAT16 = 2
		FAT32 = 3
		exFAT = 4

	class Attribute:
		READONLY = 0x01
		HIDDEN = 0x02
		SYSTEM = 0x04
		LABEL = 0x08
		DIRECTORY = 0x10
		ARCHIVE = 0x20
		LONGNAME = READONLY | HIDDEN | SYSTEM | LABEL

	class FileNotFoundError(Exception):
		def __init__(self, path):
			self.path = path
		def __str__(self):
			return "The file or directory \"%s\" doesn't exist" % self.path

	def __init__(self, fd):
		self._logger = logging.getLogger ("FAT")
		#~ self._logger.setLevel (logging.DEBUG)
		self.fd = fd
		self.__start = fd.tell()
		self.info = self.__parse_bootsector()
		self._logger.debug ("FAT INFO: %s", self.info)

		# Calculate the offset to the first FAT
		# fat_begin_lba (but n res sect is mult by ss)
		self.__fat_start = self.__start + self.info["reserved_sectors"] * self.info["sector_size"]

		self.fat_type, self.EOF, self.__num_clusters = self.__determine_type()
		self._logger.debug ("FAT Type: %s", self.fat_type)
		self._logger.debug ("Number of clusters: %u", self.__num_clusters)

		# Calculate the offset to the root directory
		# cluster_begin_lba
		if "root_start_cluster" in self.info and self.info["root_start_cluster"] is not None:
			#~ assert self.info["root_start_cluster"] == 2
			self.__data_start = (self.info["reserved_sectors"] + (self.info["num_fats"] * self.info["sectors_per_fat"])) * self.info["sector_size"]
			self.__root_dir = self.cluster_to_offset (self.info["root_start_cluster"])
		else:
			self.__root_dir = ((self.info["num_fats"] * self.info["sectors_per_fat"]) *
				self.info["sector_size"]) + self.__fat_start

			# Calculate the offset to the actual data start
			self.__data_start = self.__root_dir + (FAT.DIRSIZE * self.info["root_entries"])
		self._logger.debug ("root offset: %u", self.__root_dir)
		self._logger.debug ("data start: %u", self.__data_start)

	# Determines which type of FAT it is depending on the properties
	def __determine_type(self):
		root_dir_sectors = ((self.info["root_entries"] * FAT.DIRSIZE) +
			(self.info["sector_size"] - 1)) / self.info["sector_size"]
		data_sectors = self.info["total_sectors"] - (self.info["reserved_sectors"] +
			(self.info["num_fats"] * self.info["sectors_per_fat"]) + root_dir_sectors)
		num_clusters = data_sectors / self.info["sectors_per_cluster"]
		if num_clusters < 4085:
			return (FAT.Type.FAT12, FAT.EOF_FAT12, num_clusters)
		elif num_clusters < 65525:
			return (FAT.Type.FAT16, FAT.EOF_FAT16, num_clusters)
		else:
			return (FAT.Type.FAT32, FAT.EOF_FAT32, num_clusters)

	def __next_cluster(self, cluster):
		offset = self.__fat_start
		if self.fat_type == FAT.Type.FAT12:
			offset += cluster + (cluster / 2)
			self.fd.seek(offset, SEEK_SET)
			value = unpack("<H", self.fd.read(2))[0]
			return value >> 4 if cluster & 1 else value & 0xfff
		elif self.fat_type == FAT.Type.FAT16:
			offset += cluster * 2
			self.fd.seek(offset, SEEK_SET)
			return unpack("<H", self.fd.read(2))[0]
		elif self.fat_type == FAT.Type.FAT32:
			offset += cluster * 4
			self.fd.seek(offset, SEEK_SET)
			return unpack("<L", self.fd.read(4))[0]
		else:
			raise NotImplementedError

	def get_cluster_chain(self, cluster):
		chain = [cluster]
		if cluster == 0:
			return chain
		while cluster < self.EOF:
			chain.append(self.__next_cluster(cluster))
			cluster = chain[-1]
		return chain[:-1]

	def read_cluster(self, cluster):
		if cluster < 2:
			return ""
		self.fd.seek(self.cluster_to_offset(cluster))
		return self.fd.read(self.info["sectors_per_cluster"] * self.info["sector_size"])

	# Calculate the logical sector number from the cluster
	def cluster_to_offset(self, cluster):
		offset = ((cluster - 2) * self.info["sectors_per_cluster"]) * self.info["sector_size"]
		#~ print "Cluster %d is at %u" % (cluster, self.__data_start + offset)
		return self.__data_start + offset

	# Read everything we need from the bootsector
	def __parse_bootsector(self):
		data = unpack("<3x8sHBHBHHBHHHLL LHHL", self.fd.read(48))
		return {
			"oem": data[0].strip(" "),
			"sector_size": data[1],		# Bytes per sector 0x0B
			"sectors_per_cluster": data[2],		# 0x0D
			"reserved_sectors": data[3],		# 0x0E
			"num_fats": data[4],				# B 0x10
			"root_entries": data[5],			# H 0x11 (0 for FAT32)
			"total_sectors": data[6] if data[6] != 0 else data[12],		# H 0x13 (0 for FAT32) / L 0x20
			"media_descriptor": data[7],		# B 0x15
			"sectors_per_fat": data[8] if data[8] != 0 else data[13],	# H 0x16 (0 for FAT32) / L 0x24
			"sectors_per_track": data[9],		# H 0x18
			"num_heads": data[10],				# H 0x1A
			"hidden_sectors": data[11],			# L 0x1C
			"flags": data[14],					# H 0x28
			"ver": data[15],					# H 0x2A
			"root_start_cluster": data[16]		# L 0x2C
		}

	# Convert a FAT date to a date object
	def __parse_fat_date(self, v):
		year, month, day = 1980 + (v >> 9), (v >> 5) & 0x1f, v & 0x1f
		month = min(max(month, 12), 1)
		day = min(max(day, 31), 1)
		return date(year, month, day)

	# Convert a FAT timestamp to a datetime object
	def __parse_fat_datetime(self, v1, v2, v3):
		hour, minute, second = v2 >> 11 & 0x1f, v2 >> 16 & 0x3f, (v2 & 0x1f) * 2
		if v1 >= 100:
			second += 1
			v1 -= 100
		usec = v1 * 10000
		d = self.__parse_fat_date(v3)
		#~ print "DT = ", (d.year, d.month, d.day, hour, minute, second, usec)
		return datetime(d.year, d.month, d.day, hour, minute, second, usec)

	# Read and parse a FAT directory entry
	def __read_dir_entry(self):
		bas = []
		while True:
			buf = self.fd.read(FAT.DIRSIZE)
			assert len (buf) == FAT.DIRSIZE
			de = unpack("<11sBxBHHH2xHHHL", buf)

			if de[1] & FAT.Attribute.LABEL and not de[1] & FAT.Attribute.READONLY:
				# Volume label, skip
				pass
			elif de[1] & FAT.Attribute.LONGNAME == FAT.Attribute.LONGNAME:
				de = unpack("<32B", buf)	# Re-unpack as single bytes
				ba = bytearray (de[1:11] + de[14:26] + de[28:32])
				bas.insert (0, ba)	# Prepend
			else:
				break
		assert de is not None

		# Remove any trailing 0xFFFF
		bas = map (lambda ba: ba.rstrip('\xffff'), bas)
		#~ print bas

		# Remove trailing 0x0000
		if len (bas) > 0 and bas[-1][-1] == 0x00 and bas[-1][-2] == 0x00:
			bas[-1] = bas[-1][:-2]
		lfn = "".join (ba.decode ("utf16") for ba in bas)	# UCS-2 is UTF-16
		return {
			"name": lfn if lfn is not None and len (lfn) > 0 else self.__normalize_name(de[0]),
			"attributes": de[1],
			"created": self.__parse_fat_datetime(de[2], de[3], de[4]),
			"last_accessed": self.__parse_fat_date(de[5]),
			"modified": self.__parse_fat_datetime(0, de[6], de[7]),
			"cluster": de[8],
			"size": de[9],
			"direntry": self.fd.tell() - FAT.DIRSIZE
		}

	# Normalizes a 8.3 FAT filename
	def __normalize_name(self, fatname):
		if fatname[8:] == "   ":
			# Skip the dot if there is no file extension
			return fatname[:8].strip(" ")
		else:
			# Otherwise strip the spaces and dotify plus the extension
			return fatname[:8].strip(" ") + "." + fatname[8:].strip(" ")

	def _calc_checksum (self, filename):
		s = 0
		for c in filename:
			s = ((s & 1) << 7) + (s >> 1) + ord (c)
			s &= 0xFF
		return s

	def __read_dirOLD(self, offset):
		print "Seeking at %u" % offset
		self.fd.seek(offset, SEEK_SET)
		items = []
		for i in range(self.info["root_entries"]):
			de = self.__read_dir_entry()
			if not de:
				continue
			# Skip deleted files
			if de["name"][0] == '\xe9':
				continue
			# Break when we hit the first blank filename
			elif de["name"][0] == '\x00':
				break
			else:
				items.append(de)
		return items

	# For FAT32
	def __read_dir(self, stClu):
		items = []
		bas = []
		csum = None
		for clu in self.get_cluster_chain (stClu):
			offset = self.cluster_to_offset (clu)
			#~ print "Seeking to %u" % offset
			self.fd.seek(offset, SEEK_SET)
			nEnt = self.info["sectors_per_cluster"] * self.info["sector_size"] / FAT.DIRSIZE
			#~ print "Dir entries per clu: %d" % nEnt
			for i in xrange (0, nEnt):
				buf = self.fd.read(FAT.DIRSIZE)
				assert len (buf) == FAT.DIRSIZE

				# Unpack according to dir entry structure
				de = unpack("<11sBxBHHH2xHHHL", buf)
				if ord (de[0][0]) == 0xE5:
					# Deleted file, skip
					pass
				elif de[1] & FAT.Attribute.LABEL and not de[1] & FAT.Attribute.READONLY:
					# Volume label, skip
					pass
				elif de[1] & FAT.Attribute.LONGNAME == FAT.Attribute.LONGNAME:
					# LFN entry
					de = unpack("<%uB" % FAT.DIRSIZE, buf)	# Re-unpack as single bytes

					if de[0] & 0x40:
						# First lfn entry, clear list
						bas = []
						nextLfnSeqNo = (de[0] & ~0x40) - 1
					elif de[0] == nextLfnSeqNo:
						nextLfnSeqNo -= 1
						assert nextLfnSeqNo >= 0
					else:
						self._logger.warning ("Bad LFN Sequence No.: expected %u, found %u", nextLfnSeqNo, de[0])

					ba = bytearray (de[1:11] + de[14:26] + de[28:32])
					csum = de[13]
					#~ print nextLfnSeqNo + 1, csum
					bas.insert (0, ba)	# Prepend
				elif de[0][0] == '\x00':
					# First blank filename, end of directory, quit
					#~ print "--EOD--"
					break
				else:
					# Normal file/subdir entry
					if csum is not None:
						# Verify that LFN matches file
						c = self._calc_checksum (de[0])
						if c != csum:
							self._logger.error ("LFN checksum does not match")
						csum = None

					# Remove any trailing 0xFFFF in any LFN component
					bas = map (lambda ba: ba.rstrip('\xffff'), bas)
					#~ print bas

					# Remove trailing 0x0000 in last LFN component
					if len (bas) > 0 and bas[-1][-1] == 0x00 and bas[-1][-2] == 0x00:
						bas[-1] = bas[-1][:-2]
					lfn = "".join (ba.decode ("utf16") for ba in bas)	# UCS-2 is UTF-16
					dirent = {
						"name": lfn if lfn is not None and len (lfn) > 0 else self.__normalize_name(de[0]),
						"attributes": de[1],
						"created": self.__parse_fat_datetime(de[2], de[3], de[4]),
						"last_accessed": self.__parse_fat_date(de[5]),
						"modified": self.__parse_fat_datetime(0, de[6], de[7]),
						"cluster": de[8],
						"size": de[9],
						"direntry": self.fd.tell() - FAT.DIRSIZE
					}
					#~ print dirent["name"]
					items.append(dirent)

		return items

	def get_label(self):
		# FIXME: Is the label always located as the first file in the root directory?
		self.fd.seek(self.__root_dir, SEEK_SET)
		return unpack("11s", self.fd.read(11))[0].strip(" ")

	def read_file(self, path):
		path = path.lower()
		pos = path.rfind("/")
		items = self.read_dir("" if pos < 0 else path[:pos])
		if items:
			items = filter(lambda x: x["name"].lower() == path[pos+1:], items)
			if items:
				item = items[0]
				data = "".join([self.read_cluster(c) for c in self.get_cluster_chain(item["cluster"])])
				return data[:item["size"]]
		raise FAT.FileNotFoundError(path)

	# Read all files from a directory
	def read_dir(self, path=""):
		# Start with the root directory
		items = self.__read_dir(self.info["root_start_cluster"])
		#~ print "->", items
		# Filter out empty strings
		subdirs = filter(len, path.lower().split("/"))
		# Now look in all sub directories for our path
		for d in subdirs:
			# Get the one and only directory we are looking for
			items = filter(lambda x: x["attributes"] & FAT.Attribute.DIRECTORY and x["name"].lower() == d, items)
			if not items:
				raise FAT.FileNotFoundError(path)
			items = self.__read_dir(items[0]["cluster"])
		return items
