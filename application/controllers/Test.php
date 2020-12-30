<?php


class Test extends CI_Controller
{
    function __construct()
    {
        parent::__construct();
        $this->load->library('Socket' , [
            'url' => 'http://localhost:3000/'
        ]);
    }

    public function index()
    {
        $io = $this->socket->init();
        $io->emit('server_s', ['foo']);
    }
}







