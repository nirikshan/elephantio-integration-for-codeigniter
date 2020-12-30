# elephantio-integration-for-codeigniter
Connect your codeigniter application with socket.io using elephant.io


## Usage

On Controller: 

```php

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


```

On Node Server : 


```js

  var app = require('express')();
  var http = require('http').createServer(app);


  const io = require("socket.io")(http, {
    cors: {
      origin: '*',
    }
  });

  app.get('/', (req, res) => {
      res.send('<h1>hey</h1>');
  });

  io.on('connection', function (socket){

    socket.on('server_s', function (message) {

       console.log('server > ' + JSON.stringify(message))  ;

       io.emit('client_r', JSON.stringify(message));
       // You can emit data sent by elephant.io to socket.io client 
    });

    socket.on('disconnect', function () {
        console.log('SocketIO > Disconnected socket ' + socket.id);
    });
    
  });


  http.listen(3000, () => {
    console.log('listening on *:3000');
  });

```

For more detail please visit to [elephant.io](https://wisembly.github.io/elephant.io/)
