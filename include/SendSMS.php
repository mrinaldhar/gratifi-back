<?php 

class SendSMS {

	// server_url
    private static $server_url = 'http://127.0.0.1:8800/';
    // user
    private static $user = 'ankurbhartiya';
	// password
    private static $password = 'jaimatadi';
	
	// mainly for internal use
    public static function get_OTP() {
        return (mt_rand(1000,9999));
    }
	
	// this will be used to send OTP
    public static function send_OTP($mobile) {
		// INIT CURL 
		$ch = curl_init(); 
		 
		// SET URL FOR THE POST FORM LOGIN 
		curl_setopt($ch, CURLOPT_URL, self::$server_url); 
		 
		// ENABLE HTTP POST 
		curl_setopt ($ch, CURLOPT_POST, 1);
		
		$otp = (string)self::get_OTP();
						
		curl_setopt ($ch, CURLOPT_POSTFIELDS, 'User='.self::$user.'&Password='.self::$password.'&PhoneNumber='.$mobile.'&Text=Gratifi OTP: '.$otp); 
		
		curl_setopt ($ch, CURLOPT_RETURNTRANSFER, 1); 		
		 
		// EXECUTE 1st REQUEST (FORM LOGIN) 
		$response = curl_exec ($ch); 
		
		// CLOSE CURL 
		curl_close ($ch); 
	
        return $otp;
    }	
}
 
?>