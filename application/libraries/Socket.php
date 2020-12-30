<?php

require_once __DIR__.'/socketio/socket.php';

class Socket
{
    function __construct($data){
        if(!isset($data['url'])){
            echo("Bro you must give url of socket.io with port...");
        }
        $this->client = new Client(new Version2X($data['url']));
    }

    public function init()
    {
        return $this->client->initialize();
    }
}


?>