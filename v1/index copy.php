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
        // validating api key
        if (!$db->isValidApiKey($api_key)) {
            // api key is not present in users table
            $response["error"] = true;
            $response["message"] = "Access Denied. Invalid Api key";
            echoRespnse(401, $response);
            $app->stop();
        } else {
            global $user_id;
            // get user primary key id
            $user_id = $db->getUserId($api_key);
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
            $exist_business = $app->request->post('exist_business');


            // validating email address
            validateEmail($email);

            $db = new DbHandler();

            if ($exist_business == 'Existing Business') {
            $businessid = $app->request->post('businessid');
            $res = $db->createUser($name, $email, $password, $age, $businessid, $gender, $city, $country, $mobile);

            }
            else if ($exist_business == 'New Business') {

            $res = $db->createUser($name, $email, $password, $age, $businessid, $gender, $city, $country, $mobile);


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
    $body = '<body><div class="container-fluid"><img src="'.$obj->logo.'" style="margin-top: 40px; display:block; width:100%;" /><br /><p style="font-size:1.5em; margin:20px; text-align:center;"><a href="'.$obj->video.'"><button class="btn btn-primary" style="margin-top:40px;">Watch a cool video!</button></a></p></div></body>';
    
    }
    else if ($obj->campaign_type == 'Interstitial') {
    $body = '<body><div class="container-fluid"><img src="'.$obj->logo.'" style="margin-top: 40px; display:block; width:100%;" /><br /><p style="font-size:1.5em; margin:20px; text-align:center;">'.$obj->message.'<br /><a href="'.$obj->link.'"><button class="btn btn-primary" style="margin-top:40px;">Check in to this place on Facebook!</button></a></p></div></body>';
    
    }
    else if ($obj->campaign_type == 'Feedback Form') {
        
    $body = '<body><div class="container-fluid"><img src="'.$obj->logo.'" style="margin-top: 40px; display:block; margin-left:auto; margin-right:auto; width:65%;" /><br /><p style="font-size:1.7em; margin:20px; text-align:center;">'.$obj->question.'<br /><a href="submitform.php"><button class="btn btn-primary" style="margin-top:40px;">'.$obj->opt1.'</button></a><br /><a href="submitform.php"><button class="btn btn-primary" style="margin-top:40px;">'.$obj->opt2.'</button></a><br /><a href="submitform.php"><button class="btn btn-primary" style="margin-top:40px;">'.$obj->opt3.'</button></a></p></div></body>';
    
    }
    else if ($obj->campaign_type == 'FB Page') {
    $body = '<body><div class="container-fluid"><img src="'.$obj->logo.'" style="margin-top: 40px; display:block; width:100%;" /><br /><p style="font-size:1.5em; margin:20px; text-align:center;">'.$obj->message.'<br /><a href="'.$obj->fbpage.'"><button class="btn btn-primary" style="margin-top:40px;">Visit our Facebook Page!</button></a></p></div></body>';
        
    }
    else if ($obj->campaign_type == 'App Download') {
        
    $body = '<body><div class="container-fluid"><img src="'.$obj->logo.'" style="margin-top: 40px; display:block; width:100%;" /><br /><p style="font-size:1.5em; margin:20px; text-align:center;">'.$obj->message.'<br /><a href="'.$obj->playstore.'"><button class="btn btn-primary" style="margin-top:40px;">Download app from Google Playstore!</button></a></p></div></body>';
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
        while ($item = $result->fetch_assoc()) {
            array_push($list, $item["ssid"].'+'.$item["id"]);
        }
        array_push($response["list"], $list);
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
            $c_hotspots = "hi";
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
            $user_id = $db->getUserId($_SESSION['apikey']);
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
/**
 * Listing all tasks of particual user
 * method GET
 * url /tasks          
 */
// $app->get('/tasks', 'authenticate', function() {
//             global $user_id;
//             $response = array();
//             $db = new DbHandler();

//             // fetching all user tasks
//             $result = $db->getAllUserTasks($user_id);

//             $response["error"] = false;
//             $response["tasks"] = array();

//             // looping through result and preparing tasks array
//             while ($task = $result->fetch_assoc()) {
//                 $tmp = array();
//                 $tmp["id"] = $task["id"];
//                 $tmp["task"] = $task["task"];
//                 $tmp["status"] = $task["status"];
//                 $tmp["createdAt"] = $task["created_at"];
//                 array_push($response["tasks"], $tmp);
//             }

//             echoRespnse(200, $response);
//         });

/**
 * Listing single task of particual user
 * method GET
 * url /tasks/:id
 * Will return 404 if the task doesn't belongs to user
 */
// $app->get('/tasks/:id', 'authenticate', function($task_id) {
//             global $user_id;
//             $response = array();
//             $db = new DbHandler();

//             // fetch task
//             $result = $db->getTask($task_id, $user_id);

//             if ($result != NULL) {
//                 $response["error"] = false;
//                 $response["id"] = $result["id"];
//                 $response["task"] = $result["task"];
//                 $response["status"] = $result["status"];
//                 $response["createdAt"] = $result["created_at"];
//                 echoRespnse(200, $response);
//             } else {
//                 $response["error"] = true;
//                 $response["message"] = "The requested resource doesn't exists";
//                 echoRespnse(404, $response);
//             }
//         });

/**
 * Creating new task in db
 * method POST
 * params - name
 * url - /tasks/
 */
// $app->post('/tasks', 'authenticate', function() use ($app) {
//             // check for required params
//             verifyRequiredParams(array('task'));

//             $response = array();
//             $task = $app->request->post('task');

//             global $user_id;
//             $db = new DbHandler();

//             // creating new task
//             $task_id = $db->createTask($user_id, $task);

//             if ($task_id != NULL) {
//                 $response["error"] = false;
//                 $response["message"] = "Task created successfully";
//                 $response["task_id"] = $task_id;
//                 echoRespnse(201, $response);
//             } else {
//                 $response["error"] = true;
//                 $response["message"] = "Failed to create task. Please try again";
//                 echoRespnse(200, $response);
//             }            
//         });

/**
 * Updating existing task
 * method PUT
 * params task, status
 * url - /tasks/:id
 */
// $app->put('/tasks/:id', 'authenticate', function($task_id) use($app) {
//             // check for required params
//             verifyRequiredParams(array('task', 'status'));

//             global $user_id;            
//             $task = $app->request->put('task');
//             $status = $app->request->put('status');

//             $db = new DbHandler();
//             $response = array();

//             // updating task
//             $result = $db->updateTask($user_id, $task_id, $task, $status);
//             if ($result) {
//                 // task updated successfully
//                 $response["error"] = false;
//                 $response["message"] = "Task updated successfully";
//             } else {
//                 // task failed to update
//                 $response["error"] = true;
//                 $response["message"] = "Task failed to update. Please try again!";
//             }
//             echoRespnse(200, $response);
//         });

/**
 * Deleting task. Users can delete only their tasks
 * method DELETE
 * url /tasks
 */
// $app->delete('/tasks/:id', 'authenticate', function($task_id) use($app) {
//             global $user_id;

//             $db = new DbHandler();
//             $response = array();
//             $result = $db->deleteTask($user_id, $task_id);
//             if ($result) {
//                 // task deleted successfully
//                 $response["error"] = false;
//                 $response["message"] = "Task deleted succesfully";
//             } else {
//                 // task failed to delete
//                 $response["error"] = true;
//                 $response["message"] = "Task failed to delete. Please try again!";
//             }
//             echoRespnse(200, $response);
//         });

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
