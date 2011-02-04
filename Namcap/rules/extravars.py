# 
# namcap rules - extravars
# Copyright (C) 2003-2009 Jesse Young <jesseyoung@gmail.com>
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

import re
from Namcap.ruleclass import *

class package(Pkgbuildrule):
	name = "extravars"
	description = "Verifies that extra variables start with an underscore"
	def analyze(self, pkginfo, tar):
		stdvars = ['arch', 'license', 'depends', 'makedepends',
				 'provides', 'conflicts' , 'replaces', 'backup',
				 'source', 'noextract', 'md5sums', 'sha1sums',
				 'sha256sums', 'sha384sums', 'sha512sums', 'pkgname',
				 'pkgver', 'pkgrel', 'pkgdesc', 'url', 'install']
		ret = [[], [], []]
		for i in pkginfo.pkgbuild:
			m = re.match('[\s]*([^\s=]*)\s*=', i)
			if m:
				varname = m.group(1)
				if varname not in stdvars:
					if not varname.startswith('_'):
						ret[1].append(("extra-var-begins-without-underscore %s", varname))
		return ret
# vim: set ts=4 sw=4 noet: