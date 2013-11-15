#
# namcap rules - py_mtime
# Copyright (C) 2013 Kyle Keen <keener@gmail.com>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

"""
Check for py timestamps that are ahead of pyc/pyo timestamps
"""

import os
from Namcap.util import load_mtree
from Namcap.ruleclass import *

def _quick_filter(names):
	"can this package be skipped outright"
	if not names:
		return True
	found_py  = any(n.endswith('.py')  for n in names)
	found_pyc = any(n.endswith('.pyc') for n in names)
	found_pyo = any(n.endswith('.pyo') for n in names)
	if found_py and found_pyc:
		return False
	if found_py and found_pyo:
		return False
	return True

def _tar_timestamps(tar):
	"takes a tar object"
	return dict((m.name, m.mtime) for m in tar.getmembers())

def _mtree_timestamps(tar):
	"takes a tar object"
	return dict((h, a['time']) for h,a in load_mtree(tar) if 'time' in a)

def _generic_timestamps(tar):
	"works for mtree and tar"
	if '.MTREE' in tar.getnames():
		return _mtree_timestamps(tar)
	return timestamps(tar)

def _try_mtree(tar):
	"returns True if good, False if bad, None if N/A"
	if '.MTREE' not in tar.getnames():
		return None
	stamps = _mtree_timestamps(tar)
	if _quick_filter(stamps.keys()):
		return True
	return not _mtime_filter(stamps)

def _try_tar(tar):
	"returns True if good, False if bad"
	names = tar.getnames()
	if _quick_filter(names):
		return True
	mtimes = _tar_timestamps(tar)
	return not _mtime_filter(mtimes)

def _three_cache(path):
	"returns the py3 cache location"
	d,f = os.path.split(path)
	return os.path.join(d, '__pycache__', f)

def _mtime_filter(mtimes):
	"return list of bad py file names"
	bad = []
	for name, mt1 in mtimes.items():
		if not name.endswith('.py'):
			continue
		name3 = _three_cache(name)
		variants = [name+'c', name+'o', name3+'c', name3+'o']
		for v in variants:
			if v not in mtimes:
				continue
			mt2 = mtimes[v]
			if mt1 > mt2:
				bad.append(name)
				break
	return bad

class package(TarballRule):
	name = "py_mtime"
	description = "Check for py timestamps that are ahead of pyc/pyo timestamps"
	def analyze(self, pkginfo, tar):
		mtree_status = _try_mtree(tar)
		tar_status = _try_tar(tar)
		if mtree_status == False and tar_status:
			# mtree only
			self.warning = [('py-mtime-mtree-warning', ())]
		elif not tar_status:
			# tar or both
			self.errors = [('py-mtime-tar-error', ())]
		self.infos = [('py-mtime-file-name %s', f[1:]) for f in _mtime_filter(_generic_timestamps(tar))]

# vim: set ts=4 sw=4 noet:
