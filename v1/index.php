<?php ob_start();
session_start();
require '../libs/Slim/Slim.php';
require_once '../include/DbHandler.php';
require_once '../include/PassHash.php';
require_once '../include/SendSMS.php';


\Slim\Slim::registerAutoloader();

$app = new \Slim\Slim();

// User id from db - Global Variable
$user_id = NULL;

/**
 * Adding Middle Layer to authenticate every request
 * Checking if the request has valid api key in the 'Authorization' header
 */
function authenticate(\Slim\Route $route) {
    // Getting request headers
    $headers = apache_request_headers();
    $response = array();
    $app = \Slim\Slim::getInstance();

    // Verifying Authorization Header
    if (isset($headers['Authorization'])) {
        $db = new DbHandler();

        // get the api key
        $api_key = $headers['Authorization'];
        $user_type = $headers['User_Type'];
        // validating api key
        if (!$db->isValidApiKey($api_key, $user_type)) {
            // api key is not present in users table
            $response["error"] = true;
            $response["message"] = "Access Denied. Invalid Api key";
            echoRespnse(401, $response);
            $app->stop();
        } else {
            global $user_id;
            // get user primary key id
            $user_id = $db->getUserId($api_key, $user_type);
        }
    } else {
        // api key is missing in header
        $response["error"] = true;
        $response["message"] = "Api key is misssing";
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * ----------- METHODS WITHOUT AUTHENTICATION ---------------------------------
 */
 
 /**
 * OTP Generation
 * url - /otp_generate
 * method - POST
 * params - mobile
 */
$app->post('/otp_generate', function() use ($app) {
            
            // check for required params
            verifyRequiredParams(array('mobile'));
            
            $response = array();

            // reading post params            
            $mobile = $app->request->post('mobile');
            
            // validating mobile
            validateMobile($mobile);
            
            $otp = SendSMS::send_OTP($mobile);          
            //$otp = '1234';
            
            $db = new DbHandler();
            $res = $db->createOTP($mobile, $otp);
                        
            if ($res == OTP_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "OTP inserted successfully";
            } else if ($res == OTP_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while inserting OTP";            
            }
            // echo json response
            echoRespnse(201, $response);
        });
        

/**
 * User Registration and Login of App User
 * url - /register_login_app_user
 * method - POST
 * params - mobile, otp
 */
$app->post('/register_login_app_user', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('mobile', 'otp'));

            $response = array();

            // reading post params
            $mobile = $app->request->post('mobile');
            $otp = $app->request->post('otp');            

            $db = new DbHandler();  
            $res = $db->createAppUser($mobile, $otp);

            if ($res == APP_USER_CREATED_SUCCESSFULLY || $res == APP_USER_ALREADY_EXISTED) {
                // get the user by email
                $user = $db->getAppUserByMobile($mobile);

                if ($user != NULL) {
                    $response["error"] = false;
                    $response['mobile'] = $user['mobile'];                    
                    $response['apiKey'] = $user['api_key'];
                    $response['createdAt'] = $user['created_at'];
                } else {
                    // unknown error occurred
                    $response['error'] = true;
                    $response['message'] = "An error occurred. Please try again";
                }
            } else if ($res == APP_USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";            
            }               
            
            // echo json response
            echoRespnse(201, $response);
        });

 
/**
 * User Registration
 * url - /register
 * method - POST
 * params - name, email, password
 */
$app->post('/register', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('name', 'email', 'password', 'age', 'gender', 'city', 'country', 'mobile', 'exist_business'));

            $response = array();

            // reading post params
            $name = $app->request->post('name');
            $email = $app->request->post('email');
            $password = $app->request->post('password');
            $country = $app->request->post('country');
            $age = $app->request->post('age');
            $gender = $app->request->post('gender');
            $city = $app->request->post('city');
            
            $mobile = $app->request->post('mobile');
            $user_type = $app->request->post('user_type');

            $exist_business = $app->request->post('exist_business');


            // validating email address
            validateEmail($email);

            $db = new DbHandler();

            if ($exist_business == 'Existing Business') {
            $businessid = $app->request->post('businessid');
            $res = $db->createUser($name, $email, $password, $age, $businessid, $gender, $city, $country, $mobile, $user_type);

            }
            else if ($exist_business == 'New Business') {
            $businessname = $app->request->post('businessname');
            $businesscity = $app->request->post('businesscity');
            $businessaddress = $app->request->post('businessaddress');
            $businessphone = $app->request->post('businessphone');

            $db->addBusiness($businessname, $businessaddress, $businesscity, $businessphone);
            $businessarray = $db->getBusinessIdFromDetails($businessname, $businessaddress, $businesscity, $businessphone);
            
            while ($items = $businessarray->fetch_assoc()) {   
            $thisid = $items['id'];
            $res = $db->createUser($name, $email, $password, $age, $thisid, $gender, $city, $country, $mobile, $user_type);
            }

            }

            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registering";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            
            echoRespnse(201, $response);
        });

/**
 * User Login
 * url - /login
 * method - POST
 * params - email, password
 */
$app->post('/login', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('email', 'password'));

            // reading post params
            $email = $app->request()->post('email');
            $password = $app->request()->post('password');
            $response = array();

            $db = new DbHandler();
            // check for correct email and password
            if ($db->checkLogin($email, $password)) {
                // get the user by email
                $user = $db->getUserByEmail($email);

                if ($user != NULL) {
                    $response["error"] = false;
                    $response['name'] = $user['name'];
                    $response['email'] = $user['email'];
                    $response['apiKey'] = $user['api_key'];
                    $response['createdAt'] = $user['created_at'];
                    $_SESSION['username'] = $user['name'];
                    $_SESSION['email'] = $user['email'];
                    // $_SESSION['userid'] = $user['id'];
                    $_SESSION['apikey'] = $user['api_key'];
                    $_SESSION['businessid'] = $user['business_id'];
                    $_SESSION['user_subclass'] = $user['user_type'];
                } else {
                    // unknown error occurred
                    $response['error'] = true;
                    $response['message'] = "An error occurred. Please try again";
                }
            } else {
                // user credentials are wrong
                $response['error'] = true;
                $response['message'] = 'Login failed. Incorrect credentials';
            }

            echoRespnse(200, $response);
        });

/*
 * ------------------------ METHODS WITH AUTHENTICATION ------------------------
 */




$app->get('/visitors/:what','authenticate',function($what) {
    if ($what == 'gender') {
        $response = array();
        $db = new DbHandler();

        $totalcount = $db->getTotalUsers($_SESSION['businessid']);
        $malecount = $db->getMaleUsersNum($_SESSION['businessid']);
        $response["error"] = false;
        $response["stats"] = array();
        $stats = array();
        $stats["total"] = $totalcount;
        $stats["male"] = $malecount;
        $stats["female"] = $totalcount-$malecount;
        array_push($response["stats"], $stats);

    }
    else if ($what == 'age') {
        $response = array();
        $db = new DbHandler();

        $result = $db->getUsersAge($_SESSION['businessid']);
        $response["error"] = false;
        $response["stats"] = array();
        $stats = array();
        $stats["l15"] = 0;
        $stats["1520"] = 0;
        $stats["2030"] = 0;
        $stats["g30"] = 0;
        $total = 0;
        while ($age = $result->fetch_assoc()) {

            $total = $total + 1;
            if ($age['fb_age']<15) {
                $stats["l15"]++;
            }
            else if ($age['fb_age'] < 20 && $age['fb_age'] >= 15) {
                $stats["1520"]++;
            }
            else if ($age['fb_age'] < 30 && $age['fb_age'] >= 20) {
                $stats["2030"]++;
            }
            else if ($age['fb_age'] >= 30) {
                $stats["g30"]++;
            }
            // array_push($response, $age);
        }
        $stats["total"] = $total;
        array_push($response["stats"], $stats);
    }
    else if ($what == 'monthly') {
        $response = array();
        $db = new DbHandler();

        $result = $db->getMonthlyFreq($_SESSION['businessid']);
        $response["error"] = false;
        $response["stats"] = array();
        $stats = array();
        while ($item = $result->fetch_assoc()) {
            $date = explode(' ', $item["login_time"])[0];
            $month = explode('-', $date)[1];
            $year = explode('-', $date)[0];
            if (array_key_exists($year.'-'.$month, $stats)) {
                $stats[$year.'-'.$month]++;
            }
            else {
                $stats[$year.'-'.$month] = 1;
            }
        }
        array_push($response["stats"], $stats);
    }
    else if ($what == 'total') {
        $response = array();
        $db = new DbHandler();

        $result = $db->getVisitorTotal($_SESSION['businessid']);
        $response["error"] = false;
        $response["stats"] = array();
        $stats = array();
        while ($item = $result->fetch_assoc()) {
            $stats["total"] = $item["count(*)"];
        }
        array_push($response["stats"], $stats);
    }
    else if ($what == 'interests') {
        $response = array();
        $db = new DbHandler();

        $result = $db->getVisitorInterests($_SESSION['businessid']);
        $response["error"] = false;
        $response["stats"] = array();
        $stats = array();
        while ($item = $result->fetch_assoc()) {
            $interest = explode(',', $item["fb_interests"])[0];
            if ($interest!= '')
            {
            if (array_key_exists($interest, $stats)) {
                $stats[$interest]++;
            }
            else {
                $stats[$interest] = 1;
            }
        }
        }
        array_push($response["stats"], $stats);
    }
    else if ($what == 'timesamonth') {
        $response = array();
        $db = new DbHandler();

        $result = $db->timesamonth($_SESSION['businessid']);
        $response["error"]= false;
        $response["stats"] = array();
        $stats = array();
        $currmonth = 'notset';
        $total = 0;

        while ($item = $result->fetch_assoc()) {
            $date = explode(' ', $item["login_time"])[0];
            $date = explode('-', $date);
            $month = $date[1];
            $year = $date[0];
            $month = $year.'-'.$month;
            if ($currmonth == 'notset') {
                $currmonth = $month;
                if (array_key_exists($item["app_user_id"], $stats))
                {
                $stats[$item["app_user_id"]]++;
                }
                else {
                    $stats[$item["app_user_id"]] = 1;
                }
            }
            else {
                if ($month == $currmonth) {
                    if (array_key_exists($item["app_user_id"], $stats))
                {
                $stats[$item["app_user_id"]]++;
                }
                else {
                    $stats[$item["app_user_id"]] = 1;
                }
                }
            }
        }
        array_push($response["stats"], $stats);
    }
    echoRespnse(200, $response);
});


$app->get('/allcampaigns', 'authenticate', function() {
    $response = array();
    $db = new DbHandler();

    $result = $db->getAllCampaigns($_SESSION['businessid']);
    $response["error"] = false;
    $response["details"] = array();
    $list = array();
    while ($item = $result->fetch_assoc()) {
        array_push($list, $item);
    }
    array_push($response["details"], $list);
    echoRespnse(200, $response);
});


$app->get('/campaign/:id', function($id) {
    // verifyRequiredParams(array('id'));
    $response = array();
    $db = new DbHandler();
    $result = $db->getcampaign($id);
    $response["error"] = false;
    $response["result"] = array();
    while ($item = $result->fetch_assoc()) {
        array_push($response["result"], $item);
    }
    // echoRespnse(200,$response);
    $headpart = '<html><head><title>Advertisement</title><link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.1/css/bootstrap.min.css" /><meta name="viewport" content="width=device-width, initial-scale=1"></head>';
    // $headpart = '<html><head><title>Advertisement</title><link rel="stylesheet" href="http://localhost/~sankaul/g/gratifi/css/bootstrap.min.css" /><meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no"></head>';
    
    $obj = json_encode($response["result"][0]);
    $obj = json_decode($obj);
    if ($obj->campaign_type == 'Video') {
    $body = '<body><div class="container-fluid" style="max-height:70%"><img src="'.$obj->logo.'" style="margin-top: 40px; display:block; width:100%;" /><br /><p style="font-size:1.5em; margin:20px; text-align:center;"><a href="'.$obj->video.'"><button class="btn btn-primary btn-lg" style="margin-top:40px;">Watch our latest Ad!</button></a></p></div></body>';
    
    }
    else if ($obj->campaign_type == 'Interstitial') {
    $body = '<body><div class="container-fluid" style="max-height:70%"><img src="'.$obj->logo.'" style="margin-top: 40px; display:block; width:100%;" /><br /><p style="font-size:1.5em; margin:20px; text-align:center;">'.$obj->message.'<br /><a href="'.$obj->link.'"><button class="btn btn-primary" style="margin-top:40px;">Check in to this place on Facebook!</button></a></p></div></body>';
    
    }
    else if ($obj->campaign_type == 'Feedback Form') {
        
    $body = '<body><div class="container-fluid" style="max-height:70%"><img src="'.$obj->logo.'" style="margin-top: 20px; display:block; margin-left:auto; margin-right:auto; width:65%;" /><br /><p style="font-size:1.7em; margin:0px; text-align:center;">'.$obj->question.'<br /><a href="submitform.php"><button class="btn btn-primary" style="width:100; margin-top:20px;">'.$obj->opt1.'</button></a><br /><a href="submitform.php"><button class="btn btn-primary" style="width:100; margin-top:20px;">'.$obj->opt2.'</button></a><br /><a href="submitform.php"><button class="btn btn-primary" style="width:100; margin-top:20px;">'.$obj->opt3.'</button></a></p></div></body>';
    
    }
    else if ($obj->campaign_type == 'FB Page') {
    $body = '<body><div class="container-fluid" style="max-height:70%"><img src="'.$obj->logo.'" style="margin-top: 40px; display:block; margin-left:auto; margin-right:auto; width:80%;" /><br /><p style="font-size:1.5em; margin:20px; text-align:center;">'.$obj->message.'<br /><a href="'.$obj->fbpage.'"><button class="btn btn-primary" style="margin-top:40px;">Visit our Facebook Page!</button></a></p></div></body>';
        
    }
    else if ($obj->campaign_type == 'App Download') {
        
    $body = '<body><div class="container-fluid" style="max-height:70%"><img src="'.$obj->logo.'" style="margin-top: 30px; display:block; margin-left:auto; margin-right:auto; width:80%;" /><br /><p style="font-size:1.5em; margin:0px; text-align:center;">'.$obj->message.'<br /><a href="'.$obj->playstore.'"><button class="btn btn-primary" style="margin-top:10px;">Download app from Google Playstore!</button></a></p></div></body>';
    }
    $tailpart = '</html>';
    echo $headpart . $body . $tailpart;
});

$app->delete('/campaign/:id', 'authenticate', function($id) {
$response = array();
    $db = new DbHandler();
    $result = $db->deleteCampaign($id, $_SESSION['businessid']);
    $response["error"] = false;
    echoRespnse(200, $result);
});

$app->post('/addbusiness', function() use ($app) {
    verifyRequiredParams(array('address', 'city', 'name', 'contact'));
    $response = array();
    $name = $app->request->post('name');
    $address = $app->request->post('address');
    $city = $app->request->post('city');
    $contact = $app->request->post('contact');
    $db = new DbHandler();
    $result = $db->addBusiness($name, $address, $city, $contact);
    $response["error"] = false;
    $response["message"] = "Business added successfully.";
    echoRespnse(201,$response);
});

$app->get('/businesses', function() {
$response = array();
    $db = new DbHandler();
    $result = $db->allBusinesses();
    $response["error"] = false;
    $response["result"] = array();
    while ($item = $result->fetch_assoc()) {
        array_push($response["result"], $item);
    }
    echoRespnse(200,$response);
});

$app->get('/hotspots', 'authenticate', function() use ($app) {
        $response = array();
        $db = new DbHandler();
        $response["error"] = false;
        $response["list"] = array();
        $list = array();
        $result = $db->allHotspots($_SESSION['businessid']);
        $mainlist = array();
        while ($item = $result->fetch_assoc()) {
            $list["hname"] = $item["ssid"];
            $list["hurl"] = $item["login_url"];
            $list["huname"] = $item["login_user"];
            $list["hstatus"] = $item["status"];
            $list["hid"] = $item["id"];
            array_push($mainlist, $list);
        }
        array_push($response["list"], $mainlist);
        echoRespnse(200, $response);
});

$app->post('/addcampaign', 'authenticate', function() use ($app) {

            verifyRequiredParams(array('c_type'));

            $response = array();
            $c_type = $app->request->post('c_type');
            $c_status = 'Running';
            $c_agegroup = $app->request->post('c_agegroup');
            $c_gender = $app->request->post('c_gender');
            $c_interests = $app->request->post('c_interests');
            $c_cities = $app->request->post('c_cities');
            $c_businesses = 'default';
            $c_hotspots = "default";
            $c_remarketing = 1;
            $c_views = 0;
            $c_conversions = $app->request->post('c_conversions');
            $c_cost = $app->request->post('c_cost');
            
            $link = $app->request->post('link');
            $msg = $app->request->post('msg');
            $question = $app->request->post('question');
            $linkfb = $app->request->post('linkfb');
            $linkplay = $app->request->post('linkplay');
            $opt1 = $app->request->post('opt1');
            $opt2 = $app->request->post('opt2');
            $opt3 = $app->request->post('opt3');
            $imgurl = $app->request->post('imgurl');
            $logourl = $app->request->post('logourl');
            $videourl = $app->request->post('videourl');

            $db = new DbHandler();
            $user_id = $db->getUserId($_SESSION['apikey'], 'map_user');
            $campaign_id = $db->createCampaign($_SESSION['businessid'], $user_id, $c_type, $c_hotspots, $c_views, $c_businesses, $c_interests, $c_status, $c_gender, $c_remarketing, $c_agegroup, $c_cities, $c_conversions, $c_cost, $link, $msg, $question, $linkfb, $linkplay, $opt1, $opt2, $opt3, $imgurl, $logourl, $videourl);

            // if ($campaign_id != NULL) {
                $response["error"] = false;
                $response["message"] = "Campaign created successfully";
                $response["campaign_id"] = $campaign_id;
                // echoRespnse(201, $response);
            // } else {
                // $response["error"] = true;
                // $response["message"] = "Failed to create campaign. Please try again";
                echoRespnse(201, $response);
            // }            
        });


$app->post('/addhotspot', 'authenticate', function() use ($app) {

            $response = array();
            $h_status = 'Running';
            $h_ssid = $app->request->post('h_ssid');
            $h_password = $app->request->post('h_password');
            $h_loginurl = $app->request->post('h_loginurl');
            $h_loginpwd = $app->request->post('h_loginpwd');
            $h_loginuser = $app->request->post('h_loginuser');
            $h_businessid = $_SESSION['businessid'];

            $db = new DbHandler();
            $user_id = $db->getUserId($_SESSION['apikey'], 'map_user');
            $db->createHotspot($h_ssid, $h_status, $h_password, $h_loginuser, $h_loginpwd, $h_loginurl, $h_businessid);
            $response["error"] = false;
            $response["message"] = "Campaign created successfully";
            $response["campaign_id"] = $campaign_id;
            echoRespnse(201, $response);        
        });


/**
 * Get info of a particular user
 * method GET
 * url /get_app_user_info
 * Will return 404 if the user does not exist
 */
$app->get('/get_app_user_info', 'authenticate', function() {
            global $user_id;
            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getAppUserInfo($user_id);            

            if ($result != NULL) {
                $response["error"] = false;
                $response["mobile"] = $result["mobile"];
                $response["fb_first_name"] = $result["fb_first_name"];
                $response["fb_last_name"] = $result["fb_last_name"];                
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = "The requested resource doesn't exists";
                echoRespnse(404, $response);
            }
        });

/**
 * Get campaign link
 * method GET
 * url /get_campaign_link
 * Will return 404 if error
 */
$app->get('/get_campaign_link/:id', 'authenticate', function($location_id) {
            global $user_id;
            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getCampaignLink($user_id, $location_id);

            if ($result != NULL) {
                $response["error"] = false;
                $response["campaign_id"] = $result["campaign_id"];
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = "The requested resource doesn't exists";
                echoRespnse(404, $response);
            }
        });     
        
/**
 * Updating fb info of app_user
 * method PUT
 * params 
 * url - /update_app_user_info
 */
$app->put('/update_app_user_info', 'authenticate', function() use($app) {
            // check for required params
            verifyRequiredParams(array('fb_first_name', 'fb_last_name', 'fb_email', 'fb_id', 'fb_age', 'fb_gender', 'fb_city', 'fb_country'));

            global $user_id;            
            $fb_first_name = $app->request->put('fb_first_name');
            $fb_last_name = $app->request->put('fb_last_name');
            $fb_email = $app->request->put('fb_email');
            $fb_id = $app->request->put('fb_id');
            $fb_age = $app->request->put('fb_age');
            $fb_gender = $app->request->put('fb_gender');
            $fb_city = $app->request->put('fb_city');
            $fb_country = $app->request->put('fb_country');

            $db = new DbHandler();
            $response = array();

            // updating task
            $result = $db->updateAppUserInfo($user_id, $fb_first_name, $fb_last_name, $fb_email, $fb_id, $fb_age, $fb_gender, $fb_city, $fb_country);
            if ($result) {
                // task updated successfully
                $response["error"] = false;
                $response["message"] = "User Info updated successfully";
            } else {
                // task failed to update
                $response["error"] = true;
                $response["message"] = "User Info failed to update. Please try again!";
            }
            echoRespnse(200, $response);
        });

 
 /**
 * App Session
 * url - /new_app_session
 * method - POST
 * params - location_id
 */
$app->post('/new_app_session', 'authenticate', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('location_id'));
            
            $response = array();

            // reading post params            
            $location_id = $app->request->post('location_id');          
            
            global $user_id;
            
            $db = new DbHandler();
            $res = $db->createAppSession($user_id, $location_id);
                        
            if ($res) {
                $response["error"] = false;
                $response["message"] = "App Session created successfully";
            } else{
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while creating app session";            
            }
            // echo json response
            echoRespnse(201, $response);
        });


/**
 * Get hotspot info
 * method GET
 * url /get_hotspot_info/:id
 * Will return 404 if error
 */
$app->get('/get_hotspot_info/:id', 'authenticate', function($location_id) {
            global $user_id;
            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getHotspotInfo($user_id, $location_id);

            if ($result != NULL) {
                $response["error"] = false;
                $response["business_id"] = $result["business_id"];
                $response["login_url"] = $result["login_url"];
                $response["login_user"] = $result["login_user"];
                $response["login_password_hash"] = $result["login_password_hash"];
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = "The requested resource doesn't exists";
                echoRespnse(404, $response);
            }
        });     
    
 /**
 * Post Campaign Activity
 * url - /post_campaign_activity
 * method - POST
 * params - campaign id
 */
$app->post('/post_campaign_activity', 'authenticate', function() use ($app) {
            
            // check for required params
            verifyRequiredParams(array('campaign_id'));
            
            global $user_id;
            $response = array();

            // reading post params            
            $campaign_id = $app->request->post('campaign_id');
                        
            $db = new DbHandler();
            $res = $db->postCampaignActivity($user_id, $campaign_id);           
                        
            if ($res) {
                $response["error"] = false;
                $response["message"] = "Campaign Actvity Posted successfully";
            } else {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while posting campaign activity";            
            }
            // echo json response
            echoRespnse(201, $response);
        });
    
        




/**
 * Verifying required params posted or not
 */
function verifyRequiredParams($required_fields) {
    $error = false;
    $error_fields = "";
    $request_params = array();
    $request_params = $_REQUEST;
    // Handling PUT request params
    if ($_SERVER['REQUEST_METHOD'] == 'PUT') {
        $app = \Slim\Slim::getInstance();
        parse_str($app->request()->getBody(), $request_params);
    }
    foreach ($required_fields as $field) {
        if (!isset($request_params[$field]) || strlen(trim($request_params[$field])) <= 0) {
            $error = true;
            $error_fields .= $field . ', ';
        }
    }

    if ($error) {
        // Required field(s) are missing or empty
        // echo error json and stop the app
        $response = array();
        $app = \Slim\Slim::getInstance();
        $response["error"] = true;
        $response["message"] = 'Required field(s) ' . substr($error_fields, 0, -2) . ' is missing or empty';
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * Validating email address
 */
function validateEmail($email) {
    $app = \Slim\Slim::getInstance();
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $response["error"] = true;
        $response["message"] = 'Email address is not valid';
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * Validating mobile
 */
function validateMobile($mobile) {
    $app = \Slim\Slim::getInstance();
    
    if(!is_numeric($mobile) || strlen($mobile) < 10) {
      $response = "Please provide a valid number";
      echoRespnse(400, $response);
      $app->stop();
   }   
}

/**
 * Echoing json response to client
 * @param String $status_code Http response code
 * @param Int $response Json response
 */
function echoRespnse($status_code, $response) {
    $app = \Slim\Slim::getInstance();
    // Http response code
    $app->status($status_code);

    // setting response content type to json
    $app->contentType('application/json');

    echo json_encode($response);

}



$app->run();
?>
