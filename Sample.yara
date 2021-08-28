rule Sample
{
  meta:
	description = "Rule to identify Banload malware"
	author = "jerald"
  strings:
	$a = "http://th.symcb.com" nocase
	$b = "https://www.thawte.com/" nocase
	$c = "M2 AGRO DESENVOLVIMENTO DE SISTEMAS LTDA110" nocase
	$d = "M2 AGRO DESENVOLVIMENTO DE SISTEMAS LTDA0" nocase
	$e = "C:\\Program Files\\AVAST Software\\Avast\\AvastUI.exe" wide ascii
	$f = "C:\\Program Files\\AVAST Software\\Avast\\AvLaunch.exe" wide ascii
	$g = "C:\\Program Files\\AVAST Software\\Avast\\AvEmUpdate.exe" wide ascii
	$h = "C:\\Program Files\\AVG\\Antivirus\\AvEmUpdate.exe" wide ascii
	$i = "C:\\Program Files\\AVG\\Antivirus\\AVGUI.exe" wide ascii
	$j = "F:\\Sistema\\Drivers-Denis\\FileDelete\\FileDelete\\x64\\Debug\\B.pdb" wide ascii
	
   

  condition:
    $a and 
	($b and $c and $d) or
	// digital certificate intended to evade security solutions
	($e or $f or $g) and ($h or $i) or
	// the malware tries to delete AV solutions
	$j
}
