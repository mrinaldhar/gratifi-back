<?php

/**
 * Class to handle all db operations
 * This class will have CRUD methods for database tables
 *
 * @author Ravi Tamada
 * @link URL Tutorial link
 */
class DbHandler {

    private $conn;

    function __construct() {
        require_once dirname(__FILE__) . '/DbConnect.php';
        // opening db connection
        $db = new DbConnect();
        $this->conn = $db->connect();
    }

    /* ------------- `users` table method ------------------ */

    /**
     * Creating otp
     * @param Int $mobile Mobile number
     * @param Int $otp Sent OTP     
     */
    public function createOTP($mobile, $otp) {        
        $response = array();
        
        // insert query
        $stmt = $this->conn->prepare("INSERT INTO otp(mobile, otp) values(?, ?)");
        $stmt->bind_param("ii", $mobile, $otp);

        $result = $stmt->execute();

        $stmt->close();

        // Check for successful insertion
        if ($result) {
            // User successfully inserted
            return OTP_CREATED_SUCCESSFULLY;
        } else {
            // Failed to create user
            return OTP_CREATE_FAILED;
        }

        return $response;
    }
    
    /**
     * Creating new App user
     * @param String $mobile Mobile number
     * @param String $otp OTP     
     */
    public function createAppUser($mobile, $otp) {        
        $response = array();
        
        if(!$this->verifyOTP($mobile, $otp)){
            return APP_USER_CREATE_FAILED;
        }

        // First check if user already existed in db
        if (!$this->isAppUserExists($mobile)) {

            // Generating API key
            $api_key = $this->generateApiKey();

            // insert query
            $stmt = $this->conn->prepare("INSERT INTO app_user(mobile, api_key, status) values(?, ?, 1)");
            $stmt->bind_param("is", $mobile, $api_key);

            $result = $stmt->execute();

            $stmt->close();

            // Check for successful insertion
            if ($result) {
                // User successfully inserted
                return APP_USER_CREATED_SUCCESSFULLY;
            } else {
                // Failed to create user
                return APP_USER_CREATE_FAILED;
            }
        } else {
            // User with same email already existed in the db
            return APP_USER_ALREADY_EXISTED;
        }

        return $response;
    }
 /**
       * Get Business id
       * @param String $hotspot_id
           * @return business_id
       */
      private function getBusinessId($hotspot_id) {
                  $stmt = $this->conn->prepare("SELECT h.business_id from hotspot h WHERE h.id = ?");
          $stmt->bind_param("s", $hotspot_id);
          if ($stmt->execute()) {
              $stmt->bind_result($business_id);
              // TODO
              // $task = $stmt->get_result()->fetch_assoc();
              $stmt->fetch();
              $stmt->close();
  
                          return $business_id;
          } else {
              return NULL;
          }
          }
    /**
     * Fetching app user info
     * @param String $mobile of the user
     */
    public function getAppUserInfo($user_id) {
        $stmt = $this->conn->prepare("SELECT u.mobile, u.fb_first_name, u.fb_last_name from app_user u WHERE u.id = ?");
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($mobile, $fb_first_name, $fb_last_name);
            // TODO
            // $task = $stmt->get_result()->fetch_assoc();
            $stmt->fetch();
            $res["mobile"] = $mobile;
            $res["fb_first_name"] = $fb_first_name;
            $res["fb_last_name"] = $fb_last_name;            
            $stmt->close();
            return $res;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching campaign link
     * @param String $mobile of the user
     */
    public function getCampaignLink($user_id, $location_id) {   
        $hotspot_id = $this->getHotspotId($location_id);
        if($hotspot_id != NULL){            
            $stmt1 = $this->conn->prepare("SELECT c.id from campaign c WHERE c.target_hotspots = ?");
            $stmt1->bind_param("i", $hotspot_id);
            if ($stmt1->execute()) {
                $res = array();
                $stmt1->bind_result($campaign_id);
                // TODO
                // $task = $stmt->get_result()->fetch_assoc();
                $stmt1->fetch();
                $res["campaign_id"] = $campaign_id;
                $stmt1->close();                
                return $res;
            } else {
                return NULL;
            }            
        } else {
            return NULL;
        }
    }
    
    /**
     * Fetching hotspot info
     * @param String $user_id, $location_id
     */
    public function getHotspotInfo($user_id, $location_id) {    
        $hotspot_id = $this->getHotspotId($location_id);
        if($hotspot_id != NULL){            
            $stmt1 = $this->conn->prepare("SELECT h.business_id, h.login_url, h.login_user, h.login_password_hash from hotspot h WHERE h.id = ?");
            $stmt1->bind_param("i", $hotspot_id);
            if ($stmt1->execute()) {
                $res = array();
                $stmt1->bind_result($business_id, $login_url, $login_user, $login_password_hash);
                // TODO
                // $task = $stmt->get_result()->fetch_assoc();
                $stmt1->fetch();
                $res["business_id"] = $business_id;
                $res["login_url"] = $login_url;
                $res["login_user"] = $login_user;
                $res["login_password_hash"] = $login_password_hash;
                $stmt1->close();                
                return $res;
            } else {
                return NULL;
            }            
        } else {
            return NULL;
        }
    }
    
    /**
     * Updating App User Info
     * @param String $fb_first_name, $fb_last_name, $fb_email, $fb_id, $fb_age, $fb_gender, $fb_city, $fb_country
     */
    public function updateAppUserInfo($user_id, $fb_first_name, $fb_last_name, $fb_email, $fb_id, $fb_age, $fb_gender, $fb_city, $fb_country) {
        $stmt = $this->conn->prepare("UPDATE app_user u set u.fb_first_name = ?, u.fb_last_name = ?, u.fb_email = ?, u.fb_id = ?, 
            u.fb_age = ?, u.fb_gender = ?, u.fb_city = ?, u.fb_country = ? WHERE u.id = ?");
        $stmt->bind_param("ssssisssi", $fb_first_name, $fb_last_name, $fb_email, $fb_id, $fb_age, $fb_gender, $fb_city, $fb_country, $user_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }   
    
    
    /**
     * Creating new app session
     * @param String $user_id user id
     * @param String $location_id
     */
    public function createAppSession($user_id, $location_id) {
        $hotspot_id = $this->getHotspotId($location_id);   
    $business_id = $this->getBusinessId($hotspot_id);     
        if($hotspot_id != NULL){    
            $stmt = $this->conn->prepare("INSERT INTO app_session(app_user_id, hotspot_id, business_id) values(?,?,?)");
            $stmt->bind_param("iii", $user_id, $hotspot_id, $business_id);
            $result = $stmt->execute();
            $stmt->close();

            return $result;
        }
        else{
            return 0;
        }
    }
    
    /**
     * Insert Campaign Activity
     * @param Int $user_id
     * @param Int $campaign_id
     */
    public function postCampaignActivity($user_id, $campaign_id) {               
        // insert query
        $stmt = $this->conn->prepare("INSERT INTO campaign_activity(app_user_id, campaign_id, view, conversion, cost) values(?, ?, 1, 1, 0)");
        $stmt->bind_param("ii", $user_id, $campaign_id);
        $result = $stmt->execute();
        $stmt->close();

        return $result;
    }

    
    /**
     * Checking for duplicate app user by mobile
     * @param String $mobile mobile to check in db
     * @return boolean
     */
    private function isAppUserExists($mobile) {
        $stmt = $this->conn->prepare("SELECT id from app_user WHERE mobile = ?");       
        $stmt->bind_param("s", $mobile);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    
    /**
     * Verifying OTP
     * @param String $mobile Mobile to check for OTP
     * @param String $otp OTP to compare
     * @return boolean
     */
    private function verifyOTP($mobile, $otp) {
        $stmt = $this->conn->prepare("SELECT otp from otp WHERE mobile = ?");       
        $stmt->bind_param("i", $mobile);
        $stmt->execute();
        $stmt->bind_result($savedOTP);
        $stmt->store_result();
        
        while($stmt->fetch()) {
            if($otp == (string)$savedOTP){
                return true;
            }
        }
        
        $stmt->close();
        
        return false;       
    }
    
    /**
     * Get Hotspot id
     * @param String $location_id
     * @return hotspot_id
     */
    private function getHotspotId($location_id) {
        $stmt = $this->conn->prepare("SELECT h.hotspot_id from hotspot_map h WHERE h.bssid = ?");        
        $stmt->bind_param("s", $location_id);
        if ($stmt->execute()) {            
            $stmt->bind_result($hotspot_id);
            // TODO
            // $task = $stmt->get_result()->fetch_assoc();
            $stmt->fetch();                     
            $stmt->close();
            
            return $hotspot_id;        
        } else {
            return NULL;
        }
    }
    
    
    
    /**
     * Creating new user
     * @param String $name User full name
     * @param String $email User login email id
     * @param String $password User login password
     */
    public function createUser($name, $email, $password, $age, $businessid, $gender, $city, $country, $mobile) {
        require_once 'PassHash.php';
        $response = array();

        // First check if user already existed in db
        if (!$this->isUserExists($email)) {
            // Generating password hash
            $password_hash = PassHash::hash($password);

            // Generating API key
            $api_key = $this->generateApiKey();

            // insert query
            $stmt = $this->conn->prepare("INSERT INTO map_user(name, email, password_hash, api_key, status, city, country, gender, business_id, age, mobile, user_type) values(?, ?, ?, ?, 1, ?, ?, ?, ?,?,?, 'Admin')");
       var_dump($this->conn);     
            $stmt->bind_param("sssssssiii", $name, $email, $password_hash, $api_key, $city, $country, $gender, intval($businessid), intval($age), intval($mobile));

            $result = $stmt->execute();

            $stmt->close();

            // Check for successful insertion
            if ($result) {
                // User successfully inserted
                return USER_CREATED_SUCCESSFULLY;
            } else {
                // Failed to create user
                return USER_CREATE_FAILED;
            }
        } else {
            // User with same email already existed in the db
            return USER_ALREADY_EXISTED;
        }

        return $response;
    }


    /**
     * Checking user login
     * @param String $email User login email id
     * @param String $password User login password
     * @return boolean User login status success/fail
     */
    public function checkLogin($email, $password) {
        // fetching user by email
        $stmt = $this->conn->prepare("SELECT password_hash FROM map_user WHERE email = ?");
        // var_dump($this->conn);
        $stmt->bind_param("s", $email);

        $stmt->execute();

        $stmt->bind_result($password_hash);

        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            // Found user with the email
            // Now verify the password

            $stmt->fetch();

            $stmt->close();

            if (PassHash::check_password($password_hash, $password)) {
                // User password is correct
                return TRUE;
            } else {
                // user password is incorrect
                return FALSE;
            }
        } else {
            $stmt->close();

            // user not existed with the email
            return FALSE;
        }
    }

    /**
     * Checking for duplicate user by email address
     * @param String $email email to check in db
     * @return boolean
     */
    private function isUserExists($email) {
        $stmt = $this->conn->prepare("SELECT id from map_user WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    

    /**
     * Fetching user by email
     * @param String $email User email id
     */
    public function getUserByEmail($email) {
        $stmt = $this->conn->prepare("SELECT name, email, api_key, status, created_at, business_id FROM map_user WHERE email = ?");
        $stmt->bind_param("s", $email);
        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $stmt->bind_result($name, $email, $api_key, $status, $created_at, $business_id);
            $stmt->fetch();
            $user = array();
            $user["name"] = $name;
            $user["email"] = $email;
            $user["api_key"] = $api_key;
            $user["status"] = $status;
            $user["created_at"] = $created_at;
            $user["business_id"] = $business_id;
            $stmt->close();
            return $user;
        } else {
            return NULL;
        }
    }

    
    public function getTotalUsers($business_id) {
        $stmt = $this->conn->prepare("SELECT count(*) FROM app_user WHERE business_id = ?");
        $stmt->bind_param("i", $business_id);
         if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $stmt->bind_result($count_total);
            $stmt->fetch();
        }
        else {
            return NULL;
        }
        return $count_total;
    }

    public function getMaleUsersNum($business_id) {
     $stmt = $this->conn->prepare("SELECT count(*) FROM app_user WHERE business_id = ? AND fb_gender = 'Male'");
        
        $stmt->bind_param("i", $business_id);
         if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $stmt->bind_result($count_male);
            $stmt->fetch();
        }
        else {
            return NULL;
        }
        return $count_male;
    }

    public function getUsersAge($business_id) {
        $stmt = $this->conn->prepare("SELECT fb_age FROM app_user WHERE business_id = ?");
        
        $stmt->bind_param("i", $business_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $stmt->close();
        return $result;
    }


    public function getMonthlyFreq($business_id){
        $stmt = $this->conn->prepare("SELECT login_time from app_session where business_id = ? order by login_time ASC");
        
        $stmt->bind_param("i", $business_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $stmt->close();
        return $result;
    }

    public function getVisitorTotal($business_id) {
        $stmt = $this->conn->prepare("SELECT count(*) from app_session where business_id = ?");
        $stmt->bind_param("i", $business_id);
        $stmt->execute();
        $total = $stmt->get_result();
        $stmt->close();
        return $total;
    }

    public function getVisitorInterests($business_id) {
        $stmt = $this->conn->prepare("SELECT fb_interests from app_user where fb_interests != '' and business_id = ?");
        $stmt->bind_param("i", $business_id);
        $stmt->execute();
        $total = $stmt->get_result();
        $stmt->close();
        return $total;
    }


    public function getAllCampaigns($business_id) {
        $stmt = $this->conn->prepare("SELECT * from campaign where business_id = ?");
        
        $stmt->bind_param("i", $business_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $stmt->close();
        return $result;
    }

    public function createCampaign($business_id, $user_id, $c_type, $c_hotspots, $c_views, $c_businesses, $c_interests, $c_status, $c_gender, $c_remarketing, $c_agegroup, $c_cities, $c_conversions, $c_cost, $link, $msg, $question, $linkfb, $linkplay, $opt1, $opt2, $opt3, $imgurl, $logourl, $videourl) {
        $stmt = $this->conn->prepare("INSERT INTO campaign(status, business_id, map_user_id, campaign_type, target_age_groups, target_gender, target_interests, target_cities, target_businesses, target_hotspots, target_remarketing, metric_views, metric_conversions, metric_total_cost, link, message, question, fbpage, playstore, opt1, opt2, opt3, image, logo, video) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
        $stmt->bind_param("siisssssssiiiisssssssssss", $c_status, intval($business_id), intval($user_id), $c_type, $c_agegroup,$c_gender,$c_interests,$c_cities,$c_businesses,$c_hotspots,intval($c_remarketing),intval($c_views),intval($c_conversions),intval($c_cost), $link, $msg, $question, $linkfb, $linkplay, $opt1, $opt2, $opt3, $imgurl, $logourl, $videourl);
        $result = $stmt->execute();
        $stmt->close();
        return $result;
    }

    public function getCampaign($id) {
        $stmt = $this->conn->prepare("SELECT * FROM campaign where id = ? LIMIT 1");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        $result = $stmt->get_result();
        $stmt->close();
        return $result;
    }

    public function deleteCampaign($id, $business_id) {

        $stmt = $this->conn->prepare("DELETE FROM campaign WHERE id = ? AND business_id = ?");
        $stmt->bind_param("ii", intval($id), intval($business_id));
        $result = $stmt->execute();
        $stmt->close();
        return 1;
        }
    public function addBusiness($name, $address, $city, $contact) {
        $stmt = $this->conn->prepare("INSERT INTO business(address, city, name, contact) VALUES (?,?,?,?)");
        $stmt->bind_param("sssi", $name, $address, $city, intval($contact));
        $result = $stmt->execute();
        $stmt->close();
        return $result;
    }

    public function allBusinesses() {
        $stmt = $this->conn->prepare("SELECT * FROM business");
        $stmt->execute();
        $result = $stmt->get_result();
        $stmt->close();
        return $result;
    }

    public function timesamonth($business_id) {
        $stmt = $this->conn->prepare("SELECT * FROM app_session WHERE business_id = ? ORDER BY login_time DESC");
        $stmt->bind_param("i", $business_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $stmt->close();
        return $result;
    }

    public function allHotspots($business_id) {
        $stmt = $this->conn->prepare("SELECT * from hotspot WHERE business_id = ?");
        $stmt->bind_param("i", $business_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $stmt->close();
        return $result;
    }
    /**
     * Fetching app user by mobile
     * @param String $email App User mobile
     */
    public function getAppUserByMobile($mobile) {
        $stmt = $this->conn->prepare("SELECT mobile, api_key, status, created_at FROM app_user WHERE mobile = ?");
        $stmt->bind_param("i", $mobile);
        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $stmt->bind_result($mobile, $api_key, $status, $created_at);
            $stmt->fetch();
            $user = array();
            $user["mobile"] = $mobile;            
            $user["api_key"] = $api_key;
            $user["status"] = $status;
            $user["created_at"] = $created_at;
            $stmt->close();
            return $user;
        } else {
            return NULL;
        }
    }

    
    /**
     * Fetching user api key
     * @param String $user_id user id primary key in user table
     */
    public function getApiKeyById($user_id) {
        $stmt = $this->conn->prepare("SELECT api_key FROM map_user WHERE id = ?");
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            // $api_key = $stmt->get_result()->fetch_assoc();
            // TODO
            $stmt->bind_result($api_key);
            $stmt->close();
            return $api_key;
        } else {
            return NULL;
        }
    }

/**
     * Fetching user id by api key
     * @param String $api_key user api key
     */
    public function getUserId($api_key, $user_type) {
        $stmt = $this->conn->prepare("SELECT id FROM ".$user_type." WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        if ($stmt->execute()) {
            $stmt->bind_result($user_id);
            $stmt->fetch();
            // TODO
            // $user_id = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $user_id;
        } else {
            return NULL;
        }
    }

  /**
     * Validating user api key
     * If the api key is there in db, it is a valid key
     * @param String $api_key user api key
     * @return boolean
     */
    public function isValidApiKey($api_key, $user_type) {
        
        $stmt = $this->conn->prepare("SELECT id from ".$user_type." WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }
    /**
     * Generating random Unique MD5 String for user Api key
     */
    private function generateApiKey() {
        return md5(uniqid(rand(), true));
    }
}

?>
