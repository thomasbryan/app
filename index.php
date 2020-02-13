<?php $a = new app(); 
class app {
  private function debug() {
    set_time_limit(30);
    error_reporting(E_ALL);
    ini_set('error_reporting', E_ALL);
    ini_set('display_errors',1);
  }
  function __construct() {
    $this->debug();
    date_default_timezone_set('America/Chicago');
    if(isset($_SERVER['HTTP_X_REQUESTED_WITH'])) { if($_SERVER['HTTP_X_REQUESTED_WITH']=='XMLHttpRequest') { $this->a = true; } }
    $this->u = explode('/',$_SERVER['REQUEST_URI']);
    $this->u[count($this->u)-1] = strtok(end($this->u),'?');
    parse_str(file_get_contents("php://input"), $this->req);
    $this->e();
    if(!empty($this->e['encryption'])) {
      $this->dsn();
      if(isset($_COOKIE)) {
        if(isset($_COOKIE['app'])) {
          $token = $_COOKIE['app'];
          $shrapnel = explode('.',$token);
          if(count($shrapnel) == 2) {
            if($shrapnel[1] == base64_encode(hash_hmac('sha256',$shrapnel[0],$this->e['encryption']))) {
              //todo check expiration
              $this->who = json_decode(base64_decode($shrapnel[0]));
            }else{
              //if encrpytion key rotation window then check old key
            }
            if($this->who) {
              //controller
              //authorization
              echo 'application logic'; exit();
            }
          }
        }
      }
      if(!$this->who) {
        if(!$this->a) { 
          if(isset($_GET['code'])) {
            if(empty($_GET['state']) || ($_GET['state'] !== $_COOKIE['state'])) {
              setcookie('state','',0,'/');
              exit('State value does not match the one initially sent');
            }
            //http()
            $data = [
              'grant_type' => 'authorization_code',
              'client_id' => $this->e['id'],
              'code' => $_GET['code'],
              'redirect_uri' => $this->e['url'],
              'client_secret' => $this->e['secret']
            ];
            $options = [
              'http' => [
                'header' => "Content-type: application/x-www-form-urlencoded\r\n",
                'method' => 'POST',
                'content' => http_build_query($data)
              ]
            ];
            $context = stream_context_create($options);
            $result = @file_get_contents($this->e['toke'], false, $context);
            $json = json_decode($result);
            //validate json
            if(!empty($json)) {
              if(isset($json->id_token)) {
                $shrapnel = explode('.',$json->id_token);
                $payload = base64_decode($shrapnel[1]);
                $claim = json_decode($payload);
                if(!empty($claim)) {
                  $email = $claim->email;
                  $name = $claim->name;
                  $users = $this->query('select user from users where email = ? limit 1',[$email]);
                  if(isset($users['res'])) {
                    $sub = false;
                    if(count($users['res']) == 1) {
                      $sub = $users['res'][0]['user'];
                    }else{
                      //revise
                      $new = $this->query('insert into `users` (user,email,name) values (uuid(),?,?)',[$email,$name]);
                      $u = $this->query('select user from users where email = ? limit 1',[$email]);
                      if(count($u['res']) == 1) {
                        $sub = $u['res'][0]['user'];
                      }
                    }
                    if($sub) {
                      $exp = time() + 86400;
                      $who = base64_encode(json_encode(['exp'=>$exp,'sub'=>$sub]));
                      setcookie('app',$who.'.'.base64_encode(hash_hmac('sha256',$who,$this->e['encryption'])),$exp,'/');
                      setcookie('state','',0,'/');
                      header('Location: '.$this->e['url']);
                      exit();
                    }
                  }
                }
              }
            }
            //http_response_code(401);
            exit('Unable to process this request');
          }else{
            if(isset($_COOKIE['state'])) {
              $state = $_COOKIE['state'];
            }else{
              $state = $this->random(32);
              setcookie('state',$state,time()+86400,'/');
            }
            header('Location: '.$this->e['rize'].'?state='.$state.'&scope='.$this->e['scopes'].'&response_type=code&client_id='.$this->e['id'].'&redirect_uri='.$this->e['url']);
            exit();
          }
        }else{
          http_response_code(401);
          exit();
        }
      }
    }else{
      if(is_writable(dirname('..'))) { 
        $auth = $url = $id = $secret = $scopes = $name = $user = $pass = $host = $key = '';
        if($this->req) {
          if(isset($this->req['auth'])) $auth = $this->req['auth'];
          if(isset($this->req['url'])) $url = $this->req['url'];
          if(isset($this->req['id'])) $id = $this->req['id'];
          if(isset($this->req['secret'])) $secret = $this->req['secret'];
          if(isset($this->req['scopes'])) $scopes = $this->req['scopes'];
          if(isset($this->req['name'])) $name = $this->req['name'];
          if(isset($this->req['user'])) $user = $this->req['user'];
          if(isset($this->req['pass'])) $pass = $this->req['pass'];
          if(isset($this->req['host'])) $host = $this->req['host'];
          if(isset($this->req['key'])) $key = $this->req['key'];
          if(!empty($auth)&&!empty($url)&&!empty($id)&&!empty($secret)&&!empty($scopes)&&!empty($name)&&!empty($user)&&!empty($pass)&&!empty($host)&&!empty($key)) {
            $rize = $toke = false;
            $json = json_decode(@file_get_contents($auth.'/.well-known/openid-configuration'));
            if(!empty($json)) {
              if(isset($json->authorization_endpoint)) {
                $rize = $json->authorization_endpoint;
              }
              if(isset($json->token_endpoint)) {
                $toke = $json->token_endpoint;
              }
              if($rize && $toke) {
                if(in_array('code',$json->response_types_supported)&&in_array('email',$json->claims_supported)&&in_array('name',$json->claims_supported)) {
                  touch('../.env');
                  $this->env('auth',$auth);
                  $this->env('url',$url);
                  $this->env('id',$id);
                  $this->env('secret',$secret);
                  $this->env('scopes',$scopes);
                  $this->env('rize',$rize);
                  $this->env('toke',$toke);
                  $this->env('name',$name);
                  $this->env('user',$user);
                  $this->env('pass',$pass);
                  $this->env('host',$host);
                  $this->e();
                  $this->dsn(false);
                  $db = $this->query('CREATE DATABASE IF NOT EXISTS `'.$this->e['name'].'`');
                  if(!isset($db['err'])) {
                    $this->dsn();
										$this->query('CREATE TABLE IF NOT EXISTS `users` (`user` char(36) NOT NULL,`email` varchar(255) NOT NULL,`name` varchar(100) NOT NULL,`admin` int(11) NOT NULL DEFAULT 0,PRIMARY KEY (`user`), UNIQUE KEY `users_email_unique` (`email`))');
										$this->query('CREATE TABLE IF NOT EXISTS `roles` (`role` char(36) NOT NULL,`name` varchar(100) NOT NULL,PRIMARY KEY (`role`),UNIQUE KEY `roles_name_unique` (`name`))');
                    $this->query('CREATE TABLE IF NOT EXISTS `perms` (`perm` char(36) NOT NULL,`name` varchar(100) NOT NULL,PRIMARY KEY (`perm`),UNIQUE KEY `perms_name_unique` (`name`))');
										$this->query('CREATE TABLE IF NOT EXISTS `usros` (`user` char(36) NOT NULL,`role` char(36) NOT NULL,KEY `usros_user_foreign` (`user`),KEY `usros_role_foreign` (`role`),CONSTRAINT `usros_role_foreign` FOREIGN KEY (`role`) REFERENCES `roles` (`role`) ON DELETE CASCADE,CONSTRAINT `usros_user_foreign` FOREIGN KEY (`user`) REFERENCES `users` (`user`) ON DELETE CASCADE)');
                    $this->query('CREATE TABLE IF NOT EXISTS `ropes` (`role` char(36) NOT NULL,`perm` char(36) NOT NULL,KEY `roleperm_role_foreign` (`role`),KEY `roleperm_perm_foreign` (`perm`),CONSTRAINT `roleperm_perm_foreign` FOREIGN KEY (`perm`) REFERENCES `perms` (`perm`) ON DELETE CASCADE,CONSTRAINT `roleperm_role_foreign` FOREIGN KEY (`role`) REFERENCES `roles` (`role`) ON DELETE CASCADE)');
										$this->query('CREATE TABLE IF NOT EXISTS `meta` (`meta` char(36) NOT NULL,`method` varchar(10) NOT NULL,`first` varchar(100) NOT NULL,`last` varchar(100) NOT NULL,`name` varchar(100) NOT NULL,`type` tinyint(4) UNSIGNED NOT NULL,`read` char(36) NOT NULL,`write` char(36) NOT NULL,`datum` char(36) NOT NULL,PRIMARY KEY (`meta`))');
										$this->query('CREATE TABLE IF NOT EXISTS `data` (`datum` char(36) NOT NULL,`meta` char(36) NOT NULL,`text` mediumtext NOT NULL,`user` char(36) NOT NULL,`stamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (`datum`))');
                  	$this->env('encryption',$this->random());
                  	header('Location: '.$this->e['url']);
                  	exit();
                  }
                }
              }
            }
          }
        } if(empty($url)) $url = $this->callback(); ?><!DOCTYPE html><html><head><title>App</title><style>body{font-family:arial;}div{margin-bottom:1em;clear:both;float:right;}form{margin:auto;width:400px;}label{font-weight:bold;padding-right:2em;}input,button{padding:6px 12px;color:#555;background-color:#fff;background-image:none;border:1px solid #ccc;border-radius:4px;box-shadow:inset 0 1px 1px rgba(0,0,0,.075);box-sizing:border-box;}button{background:#0063ce;color:#fff;font-weight:bold;width:195px;}</style></head><body><form method="POST"><div><label>Provider URL</label><input type="url" name="auth" value="<?= $auth ?>" required /></div><div><label>Callback URL</label><input type="url" name="url" value="<?= $url ?>" required /></div><div><label>Client ID</label><input type="text" name="id" value="<?= $id ?>" required /></div><div><label>Client Secret</label><input type="text" name="secret" value="<?= $secret ?>" required /></div><div><label>Scope</label><input type="text" name="scopes" value="<?= $scopes ?>" required /></div><div><label>Database Name</label><input type="text" name="name" value="<?= $name ?>" required /></div><div><label>User Name</label><input type="text" name="user" value="<?= $user ?>" required /></div><div><label>Password</label><input type="text" name="pass" value="<?= $pass ?>" required /></div><div><label>Database Host</label><input type="text" name="host" value="<?= $host ?>" required /></div><div><label>Encryption Key</label><input type="text" name="key" value="<?= $key ?>" required /></div><div><button type="submit">Install Application</button></div></form></body></html><?php
      }else{
        echo 'Unable to write configuration file';exit();
      }
    }
  }
  //curl();
  private function http($json) {
    $res = [];
    $req = json_decode($json);
    if(json_last_error() == JSON_ERROR_NONE) {
      if(isset($req->url)) {
        if(!isset($req->method)) $req->method = 'GET';
        $options = [
          'http' => [
            'method' => $req->method
          ]
        ];
        if(isset($req->header)) $options['http']['header'] = $req->header;
        if(isset($req->content)) $options['http']['content'] = http_build_query($req->content);
        $context = stream_context_create($options);
        $res = @file_get_contents($req->url, false, $context);
        if(!$res) {
          $res['err'] = base64_encode(json_encode(error_get_last()));
        }else{
          $json = json_decode($res);
          if(json_last_error() == JSON_ERROR_NONE) {
            $res['res'] = $json;
          }
        }
      }
    }
    /*
      res
      type = json,html,xml,string
      err
    */
    return $res;
    //more comprehensive return status. 
  }
  private function query($query = '', $execute = []) {
    $res = [];
    try {
      $db = new PDO($this->dsn,$this->user,$this->pass);
    } catch (PDOException $e) {
      $res['err'] = $e->getMessage();
      return $res;
    }
    $statement = $db->prepare($query);
    try {
      $statement->execute($execute);
    } catch(PDOException $e) {
      $res['err'] = $e->getMessage();
      return $res;
    }
    $last = $db->lastInsertId();
    if($last) {
      $res['id'] = $last;
    }else{
      $res['res'] = $statement->fetchAll(PDO::FETCH_ASSOC);
    }
    return $res;
  }
  private $a = false; /* AJAX request */
  private $e = false; /* ENV variables */
  private $u = []; /* URI segments */
  private $req = []; /* POST */
  private $res = []; /* RESPONSE */
  private $who = false; /* USER info */
  private $dsn = ''; /* Storage Connection */
  private $user = ''; /* Storage User */
  private $pass = ''; /* Storage Pass */
  private function dsn($db = true) {
    $this->dsn = 'mysql:'.'host='.$this->e['host'];
    if($db) $this->dsn .= ';dbname='.$this->e['name'];
    $this->user = $this->e['user'];
    $this->pass = $this->e['pass'];
  }
  private function callback() {
    return 'http'.((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS']!='off')?'s':'').'://'.$_SERVER['HTTP_HOST'];
    $callback = 'http'.(isset($_SERVER['HTTPS']) ? 's':'' ).'://'.$_SERVER['HTTP_HOST'];
    /* todo random get param / more logic
    if(!isset($_GET['uri'])) {
      $callback .= '?uri';
      $file_headers = @get_headers($callback);
      if(!$file_headers || $file_headers[0] == 'HTTP/1.1 404 Not Found') {
        $callback = 'https'.substr($callback,4);
      }
      $callback = substr($callback,0,-4);
    }
    */
    return $callback;
  }
  private function grep($s,$v) {
    $pos = strpos($s,$v);
    if($pos !== false) return true;
    return false;
  }
  private function random($len=64) {
    $res='';
    $dic = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';  
    for($i=0;$i<$len;$i++) {
      $res .= $dic[rand(0,61)];
    }
    return $res;
  }
  private function utf8ize($d) {
    if(is_array($d)) {
      foreach($d as $k => $v) {
        $d[$k] = $this->utf8ize($v);
      }
    }elseif(is_string($d)) {
      return utf8_encode($d);
    }
    return $d;
  }
  private function e() {
    $env = '../.env';
    if(file_exists($env)) $this->e = parse_ini_file($env);
  }
  private function env($k,$v) {
    $env = '../.env';
    $str = file_get_contents($env);
    if(isset($this->e[$k])) {
      $old = $this->e[$k];
      $str = str_replace("{$k}={$old}\n", "{$k}={$v}\n", $str);
    }else{
      $str .= "{$k}={$v}\n";
    }
    $fp = fopen($env, 'w');
    fwrite($fp, $str);
    fclose($fp);
  }
  private function lumberjack($log=null,$lvl='info') {
    file_put_contents('../sys.log','['.date('Y-m-d H:i:s').'] ('.$lvl.') '.json_encode($log)."\n",FILE_APPEND);
  }
}
?>
