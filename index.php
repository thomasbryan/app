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
              echo 'application logic'; exit();
            }
          }
        }
      }
      if(!$this->who) {
        if(!$this->a) { 
          echo 'oauth logic'; exit();
        }else{
          http_response_code(401);
          exit();
        }
      }
    }else{
      if(is_writable(dirname('..'))) {
        echo 'install logic'; exit();
      }else{
        echo 'Unable to write configuration file';exit();
      }
    }
  }
  //curl();
  private function http($json,$err = false) {
    $res = false;
    $err = false;
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
          if($err) $this->req['err'] = base64_encode(json_encode(error_get_last()));
        }else{
          $json = json_decode($res);
          if(json_last_error() == JSON_ERROR_NONE) {
            $res = $json;
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
    try {
      $db = new PDO($this->dsn,$this->user,$this->pass);
    } catch (PDOException $e) {
      $log = 'Connection failed: '.$e->getMessage();
      $this->lumberjack($log,'error');
      //echo $log;
      return false;
    }
    #$this->lumberjack(array('q'=>$query,'t'=>$tenant),'info');
    $statement = $db->prepare($query);
    try {
      $statement->execute($execute);
    } catch(PDOException $e) {
      $log = 'Statement failed: '.$e->getMessage();
      $this->lumberjack($log,'error');
      //echo $log;
      return false;
    }
    $last = $db->lastInsertId();
    if($last) return $last;
    return $statement->fetchAll(PDO::FETCH_ASSOC);
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
  private function dsn() {
    $this->dsn = $this->e['db'].':'.'host='.$this->e['host'].';dbname='.$this->e['name'];
    $this->user = $this->e['user'];
    $this->pass = $this->e['pass'];
  }
  private function callback() {
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
  private function token($user,$name) {
    $json = [
      'Expr' => date('U',strtotime('+1 day')),
      'Name' => $name,
      'User' => $user,
    ];
    $this->who = (object) $json;
    $claim = base64_encode(json_encode($json));
    $encrypt = $this->e['encryption'];
    setcookie('index',$claim.'.'.base64_encode(hash_hmac('sha256',$claim,$encrypt)), time() + 86400,'/');
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
    $old = $this->e[$k];
    $str = str_replace("{$k}={$old}\n", "{$k}={$v}\n", $str);
    $fp = fopen($env, 'w');
    fwrite($fp, $str);
    fclose($fp);
  }
  private function lumberjack($log=null,$lvl='info') {
    file_put_contents('../sys.log','['.date('Y-m-d H:i:s').'] ('.$lvl.') '.json_encode($log)."\n",FILE_APPEND);
  }
}
?>
