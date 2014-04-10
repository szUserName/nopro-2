<html>
<body>
Sometimes<br />
<?php
	if (isset($_POST['data']))
	{
		//echo "Tnx data<br /><pre>" . $_POST['data'] . "</pre><br />";
	//	exit();
	}
	if (isset($_POST['etag']))
	{
		echo "Tnx tag<br /><pre>" . $_POST['etag'] . "</pre><br />";	
	}
	$filename = "/root/combnpr/raz";
	if (file_exists($filename)) {
	        $file=fopen("$filename","r");
		while ($buffer = fgets($file,4000)) {
			$buffer = "<!--" . trim($buffer) . "-->";
			echo $buffer;
		}	
		fclose($file);
        	//die;
	}
?>
</body>
</html>
