# -*- mode: python -*-
added_files = [
	('js','js'),
	('css','css'),
	('fonts', 'fonts'),
	('images', 'images'),
	('incident_report.html', 'incident_report.html')
 	]

a = Analysis(['incident_report.py'],
	     pathex=['/mnt/hgfs/jmcfarland/Projects/cb-reporting'],             
             hiddenimports=['unicodedata'],
	     datas=added_files,
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='incident-report',
          debug=False,
          strip=False,
          upx=True,
          console=True )
