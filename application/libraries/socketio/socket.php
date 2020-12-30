<?php



// require_once __DIR__.'/Exception/MalformedUrlException.php';

class MalformedUrlException extends InvalidArgumentException
{
    public function __construct($url, Exception $previous = null)
    {
        parent::__construct(sprintf('The url "%s" seems to be malformed', $url), 0, $previous);
    }
}



// require_once __DIR__.'/Exception/ServerConnectionFailureException.php';


class ServerConnectionFailureException extends RuntimeException
{
    public function __construct(Exception $previous = null)
    {
        parent::__construct('An error occurred while trying to establish a connection to the server', 0, $previous);
    }
}



// 
// require_once __DIR__.'/Exception/SocketException.php';

// namespace socketio\Exception;
// use RuntimeException;

class SocketException extends RuntimeException
{
    public function __construct($errno, $error, \Exception $previous = null)
    {
        parent::__construct(sprintf('There was an error while attempting to open a connection to the socket (Err #%d : %s)', $errno, $error), $errno, $previous);
    }
}



// require_once __DIR__.'/Exception/UnsupportedActionException.php';


class UnsupportedActionException extends BadMethodCallException
{
    public function __construct(EngineInterface $engine, $action, Exception $previous = null)
    {
        parent::__construct(sprintf('The action "%s" is not supported by the engine "%s"', $engine->getName(), $action), 0, $previous);
    }
}



// require_once __DIR__.'/Payload/Decoder.php';


class Decoder extends AbstractPayload implements Countable
{
    private $payload;
    private $data;

    private $length;

    /** @param string $payload Payload to decode */
    public function __construct($payload)
    {
        $this->payload = $payload;
    }

    public function decode()
    {
        if (null !== $this->data) {
            return;
        }

        $length = count($this);

        // if ($payload !== null) and ($payload packet error)?
        // invalid websocket packet data or not (text, binary opCode)
        if (3 > $length) {
            return;
        }

        $payload = array_map('ord', str_split($this->payload));

        $this->fin = ($payload[0] >> 0b111);

        $this->rsv = [($payload[0] >> 0b110) & 0b1,  // rsv1
                      ($payload[0] >> 0b101) & 0b1,  // rsv2
                      ($payload[0] >> 0b100) & 0b1]; // rsv3

        $this->opCode = $payload[0] & 0xF;
        $this->mask   = (bool) ($payload[1] >> 0b111);

        $payloadOffset = 2;

        if ($length > 125) {
            $payloadOffset = (0xFFFF < $length && 0xFFFFFFFF >= $length) ? 6 : 4;
        }

        $payload = implode('', array_map('chr', $payload));

        if (true === $this->mask) {
            $this->maskKey  = substr($payload, $payloadOffset, 4);
            $payloadOffset += 4;
        }

        $data = substr($payload, $payloadOffset, $length);

        if (true === $this->mask) {
            $data = $this->maskData($data);
        }

        $this->data = $data;
    }

    public function count()
    {
        if (null === $this->payload) {
            return 0;
        }

        if (null !== $this->length) {
            return $this->length;
        }

        $length = ord($this->payload[1]) & 0x7F;

        if ($length == 126 || $length == 127) {
            $length = unpack('H*', substr($this->payload, 2, ($length == 126 ? 2 : 4)));
            $length = hexdec($length[1]);
        }

        return $this->length = $length;
    }

    public function __toString()
    {
        $this->decode();

        return $this->data ?: '';
    }
}



// require_once __DIR__.'/Payload/Encoder.php';

class Encoder extends AbstractPayload
{
    private $data;
    /** @var string */
    private $payload;

    /**
     * @param string  $data   data to encode
     * @param integer $opCode OpCode to use (one of AbstractPayload's constant)
     * @param bool    $mask   Should we use a mask ?
     */
    public function __construct($data, $opCode, $mask)
    {
        $this->data    = $data;
        $this->opCode  = $opCode;
        $this->mask    = (bool) $mask;

        if (true === $this->mask) {
            $this->maskKey = openssl_random_pseudo_bytes(4);
        }
    }

    public function encode()
    {
        if (null !== $this->payload) {
            return;
        }

        $pack   = '';
        $length = strlen($this->data);

        if (0xFFFF < $length) {
            $pack   = pack('NN', ($length & 0xFFFFFFFF00000000) >> 0b100000, $length & 0x00000000FFFFFFFF);
            $length = 0x007F;
        } elseif (0x007D < $length) {
            $pack   = pack('n*', $length);
            $length = 0x007E;
        }

        $payload = ($this->fin << 0b001) | $this->rsv[0];
        $payload = ($payload   << 0b001) | $this->rsv[1];
        $payload = ($payload   << 0b001) | $this->rsv[2];
        $payload = ($payload   << 0b100) | $this->opCode;
        $payload = ($payload   << 0b001) | $this->mask;
        $payload = ($payload   << 0b111) | $length;

        $data    = $this->data;
        $payload = pack('n', $payload) . $pack;

        if (true === $this->mask) {
            $payload .= $this->maskKey;
            $data     = $this->maskData($data);
        }

        $this->payload = $payload . $data;
    }

    public function __toString()
    {
        $this->encode();

        return $this->payload;
    }
}

// require_once __DIR__.'/Engine/AbstractSocketIO.php';

abstract class AbstractSocketIO implements EngineInterface
{
    const CONNECT      = 0;
    const DISCONNECT   = 1;
    const EVENT        = 2;
    const ACK          = 3;
    const ERROR        = 4;
    const BINARY_EVENT = 5;
    const BINARY_ACK   = 6;

    /** @var string[] Parse url result */
    protected $url;

    /** @var array cookies received during handshake */
    protected $cookies = [];

    /** @var Session Session information */
    protected $session;

    /** @var mixed[] Array of options for the engine */
    protected $options;

    /** @var resource Resource to the connected stream */
    protected $stream;

    /** @var string the namespace of the next message */
    protected $namespace = '';

    /** @var mixed[] Array of php stream context options */
    protected $context;

    public function __construct($url, array $options = [])
    {
        $this->url = $this->parseUrl($url);
        $this->options = array_replace($this->getDefaultOptions(), $options);

        if (isset($this->options['context'])) {
            $this->context = &$this->options['context'];
        }
    }

    /** {@inheritDoc} */
    public function connect()
    {
        throw new UnsupportedActionException($this, 'connect');
    }

    /** {@inheritDoc} */
    public function keepAlive()
    {
        throw new UnsupportedActionException($this, 'keepAlive');
    }

    /** {@inheritDoc} */
    public function close()
    {
        throw new UnsupportedActionException($this, 'close');
    }

    /** {@inheritDoc} */
    public function of($namespace) {
        $this->namespace = $namespace;
    }

    /**
     * Write the message to the socket
     *
     * @param integer $code    type of message (one of EngineInterface constants)
     * @param string  $message Message to send, correctly formatted
     */
    abstract public function write($code, $message = null);

    /** {@inheritDoc} */
    public function emit($event, array $args)
    {
        throw new UnsupportedActionException($this, 'emit');
    }

    /**
     * {@inheritDoc}
     *
     * Be careful, this method may hang your script, as we're not in a non
     * blocking mode.
     */
    public function read()
    {
        if (!is_resource($this->stream)) {
            return;
        }

        /*
         * The first byte contains the FIN bit, the reserved bits, and the
         * opcode... We're not interested in them. Yet.
         * the second byte contains the mask bit and the payload's length
         */
        $data = fread($this->stream, 2);
        $bytes = unpack('C*', $data);

        $mask = ($bytes[2] & 0b10000000) >> 7;
        $length = $bytes[2] & 0b01111111;

        /*
         * Here is where it is getting tricky :
         *
         * - If the length <= 125, then we do not need to do anything ;
         * - if the length is 126, it means that it is coded over the next 2 bytes ;
         * - if the length is 127, it means that it is coded over the next 8 bytes.
         *
         * But,here's the trick : we cannot interpret a length over 127 if the
         * system does not support 64bits integers (such as Windows, or 32bits
         * processors architectures).
         */
        switch ($length) {
            case 0x7D: // 125
            break;

            case 0x7E: // 126
                $data .= $bytes = fread($this->stream, 2);
                $bytes = unpack('n', $bytes);

                if (empty($bytes[1])) {
                    throw new RuntimeException('Invalid extended packet len');
                }

                $length = $bytes[1];
            break;

            case 0x7F: // 127
                // are (at least) 64 bits not supported by the architecture ?
                if (8 > PHP_INT_SIZE) {
                    throw new DomainException('64 bits unsigned integer are not supported on this architecture');
                }

                /*
                 * As (un)pack does not support unpacking 64bits unsigned
                 * integer, we need to split the data
                 *
                 * {@link http://stackoverflow.com/questions/14405751/pack-and-unpack-64-bit-integer}
                 */
                $data .= $bytes = fread($this->stream, 8);
                list($left, $right) = array_values(unpack('N2', $bytes));
                $length = $left << 32 | $right;
            break;
        }

        // incorporate the mask key if the mask bit is 1
        if (true === $mask) {
            $data .= fread($this->stream, 4);
        }

        // Split the packet in case of the length > 16kb
        while ($length > 0 && $buffer = fread($this->stream, $length)) {
            $data   .= $buffer;
            $length -= strlen($buffer);
        }

        // decode the payload
        return (string) new Decoder($data);
    }

    /** {@inheritDoc} */
    public function getName()
    {
        return 'SocketIO';
    }

    /**
     * Parse an url into parts we may expect
     *
     * @param string $url
     *
     * @return string[] information on the given URL
     */
    protected function parseUrl($url)
    {
        $parsed = parse_url($url);

        if (false === $parsed) {
            throw new MalformedUrlException($url);
        }

        $server = array_replace(['scheme' => 'http',
                                 'host'   => 'localhost',
                                 'query'  => []
                                ], $parsed);

        if (!isset($server['port'])) {
            $server['port'] = 'https' === $server['scheme'] ? 443 : 80;
        }
        
        if (!isset($server['path']) || $server['path']=='/') {
            $server['path'] = 'socket.io';
        }

        if (!is_array($server['query'])) {
            parse_str($server['query'], $query);
            $server['query'] = $query;
        }

        $server['secured'] = 'https' === $server['scheme'];

        return $server;
    }

    /**
     * Get the defaults options
     *
     * @return array mixed[] Defaults options for this engine
     */
    protected function getDefaultOptions()
    {
        return ['context'   => [],
                'debug'     => false,
                'wait'      => 100*1000,
                'timeout'   => ini_get("default_socket_timeout")];
    }
}


// require_once __DIR__.'/Engine/SocketIO/Session.php';

class Session
{
    /** @var integer session's id */
    private $id;

    /** @var integer session's last heartbeat */
    private $heartbeat;

    /** @var integer[] session's and heartbeat's timeouts */
    private $timeouts;

    /** @var string[] supported upgrades */
    private $upgrades;

    public function __construct($id, $interval, $timeout, array $upgrades)
    {
        $this->id        = $id;
        $this->upgrades  = $upgrades;
        $this->heartbeat = time();

        $this->timeouts  = ['timeout'  => $timeout,
                            'interval' => $interval];
    }

	/**
	 * The property should not be modified, hence the private accessibility on them
	 *
	 * @param string $prop
	 * @return mixed
	 */
    public function __get($prop)
    {
        static $list = ['id', 'upgrades'];

        if (!in_array($prop, $list)) {
            throw new InvalidArgumentException(sprintf('Unknown property "%s" for the Session object. Only the following are availables : ["%s"]', $prop, implode('", "', $list)));
        }

        return $this->$prop;
    }

    /**
     * Checks whether a new heartbeat is necessary, and does a new heartbeat if it is the case
     *
     * @return Boolean true if there was a heartbeat, false otherwise
     */
    public function needsHeartbeat()
    {
        if (0 < $this->timeouts['interval'] && time() > ($this->timeouts['interval'] + $this->heartbeat - 5)) {
            $this->heartbeat = time();

            return true;
        }

        return false;
    }
}


// require_once __DIR__.'/Engine/SocketIO/Version0X.php';

class Version0X extends AbstractSocketIO
{
    const CLOSE         = 0;
    const OPEN          = 1;
    const HEARTBEAT     = 2;
    const MESSAGE       = 3;
    const JOIN_MESSAGE  = 4;
    const EVENT         = 5;
    const ACK           = 6;
    const ERROR         = 7;
    const NOOP          = 8;

    const TRANSPORT_POLLING   = 'xhr-polling';
    const TRANSPORT_WEBSOCKET = 'websocket';

    /** {@inheritDoc} */
    public function connect()
    {
        if (is_resource($this->stream)) {
            return;
        }

        $this->handshake();

        $errors = [null, null];
        $host   = sprintf('%s:%d', $this->url['host'], $this->url['port']);

        if (true === $this->url['secured']) {
            $host = 'ssl://' . $host;
        }

        $this->stream = stream_socket_client($host, $errors[0], $errors[1], $this->options['timeout'], STREAM_CLIENT_CONNECT, stream_context_create($this->context));

        if (!is_resource($this->stream)) {
            throw new SocketException($errors[0], $errors[1]);
        }

        stream_set_timeout($this->stream, $this->options['timeout']);

        $this->upgradeTransport();
    }

    /** {@inheritDoc} */
    public function close()
    {
        if (!is_resource($this->stream)) {
            return;
        }

        $this->write(static::CLOSE);
        fclose($this->stream);
        $this->stream = null;
        $this->session = null;
        $this->cookies = [];
    }

    /** {@inheritDoc} */
    public function emit($event, array $args)
    {
        $this->write(static::EVENT, json_encode(['name' => $event, 'args' => $args]));
    }

    /** {@inheritDoc} */
    public function write($code, $message = null)
    {
        if (!is_resource($this->stream)) {
            return;
        }

        if (!is_int($code) || 0 > $code || 6 < $code) {
            throw new InvalidArgumentException('Wrong message type when trying to write on the socket');
        }

        $payload = new Encoder($code . '::' . $this->namespace . ':' . $message, Encoder::OPCODE_TEXT, true);
        $bytes = fwrite($this->stream, (string) $payload);

        // wait a little bit of time after this message was sent
        usleep($this->options['wait']);

        return $bytes;
    }

    /** {@inheritDoc} */
    public function of($namespace) {
        parent::of($namespace);

        $this->write(static::OPEN);
    }

    /** {@inheritDoc} */
    public function getName()
    {
        return 'SocketIO Version 0.X';
    }

    /** {@inheritDoc} */
    protected function getDefaultOptions()
    {
        $defaults = parent::getDefaultOptions();

        $defaults['protocol']  = 1;
        $defaults['transport'] = static::TRANSPORT_WEBSOCKET;

        return $defaults;
    }

    /** Does the handshake with the Socket.io server and populates the `session` value object */
    protected function handshake()
    {
        if (null !== $this->session) {
            return;
        }

        $context = $this->context;

        if (!isset($context[$this->url['secured'] ? 'ssl' : 'http'])) {
            $context[$this->url['secured'] ? 'ssl' : 'http'] = [];
        }

        $context[$this->url['secured'] ? 'ssl' : 'http']['timeout'] = (float) $this->options['timeout'];

        $url = sprintf('%s://%s:%d/%s/%d', $this->url['scheme'], $this->url['host'], $this->url['port'], trim($this->url['path'], '/'), $this->options['protocol']);

        if (isset($this->url['query'])) {
            $url .= '/?' . http_build_query($this->url['query']);
        }

        $result = @file_get_contents($url, false, stream_context_create($context));

        if (false === $result) {
            throw new ServerConnectionFailureException;
        }

        $sess = explode(':', $result);
        $decoded['sid'] = $sess[0];
        $decoded['pingInterval'] = $sess[1];
        $decoded['pingTimeout'] = $sess[2];
        $decoded['upgrades'] = array_flip(explode(',', $sess[3]));

        if (!in_array('websocket', $decoded['upgrades'])) {
            throw new UnsupportedTransportException('websocket');
        }

        $cookies = [];
        foreach ($http_response_header as $header) {
            if (preg_match('/^Set-Cookie:\s*([^;]*)/i', $header, $matches)) {
                $cookies[] = $matches[1];
            }
        }
        $this->cookies = $cookies;

        $this->session = new Session($decoded['sid'], $decoded['pingInterval'], $decoded['pingTimeout'], $decoded['upgrades']);
    }

    /** Upgrades the transport to WebSocket */
    private function upgradeTransport()
    {
        if (!array_key_exists('websocket', $this->session->upgrades)) {
            return new UnsupportedTransportException('websocket');
        }

        $url = sprintf('/%s/%d/%s/%s', trim($this->url['path'], '/'), $this->options['protocol'], $this->options['transport'], $this->session->id);
        if (isset($this->url['query'])) {
            $url .= '/?' . http_build_query($this->url['query']);
        }

        $key = base64_encode(sha1(uniqid(mt_rand(), true), true));

        $origin = '*';
        $headers = isset($this->context['headers']) ? (array) $this->context['headers'] : [] ;

        foreach ($headers as $header) {
            $matches = [];

            if (preg_match('`^Origin:\s*(.+?)$`', $header, $matches)) {
                $origin = $matches[1];
                break;
            }
        }

        $request = "GET {$url} HTTP/1.1\r\n"
                 . "Host: {$this->url['host']}\r\n"
                 . "Upgrade: WebSocket\r\n"
                 . "Connection: Upgrade\r\n"
                 . "Sec-WebSocket-Key: {$key}\r\n"
                 . "Sec-WebSocket-Version: 13\r\n"
                 . "Origin: {$origin}\r\n";

        if (!empty($this->cookies)) {
            $request .= "Cookie: " . implode('; ', $this->cookies) . "\r\n";
        }

        $request .= "\r\n";

        fwrite($this->stream, $request);
        $result = fread($this->stream, 12);

        if ('HTTP/1.1 101' !== $result) {
            throw new UnexpectedValueException(sprintf('The server returned an unexpected value. Expected "HTTP/1.1 101", had "%s"', $result));
        }

        // cleaning up the stream
        while ('' !== trim(fgets($this->stream)));
    }
}

// require_once __DIR__.'/Engine/SocketIO/Version1X.php';

class Version1X extends AbstractSocketIO
{
    const TRANSPORT_POLLING   = 'polling';
    const TRANSPORT_WEBSOCKET = 'websocket';

    /** {@inheritDoc} */
    public function connect()
    {
        if (is_resource($this->stream)) {
            return;
        }

        $this->handshake();

        $errors = [null, null];
        $host   = sprintf('%s:%d', $this->url['host'], $this->url['port']);

        if (true === $this->url['secured']) {
            $host = 'ssl://' . $host;
        }

        $this->stream = stream_socket_client($host, $errors[0], $errors[1], $this->options['timeout'], STREAM_CLIENT_CONNECT, stream_context_create($this->context));

        if (!is_resource($this->stream)) {
            throw new SocketException($errors[0], $errors[1]);
        }

        stream_set_timeout($this->stream, $this->options['timeout']);

        $this->upgradeTransport();
    }

    /** {@inheritDoc} */
    public function close()
    {
        if (!is_resource($this->stream)) {
            return;
        }

        $this->write(EngineInterface::CLOSE);

        fclose($this->stream);
        $this->stream = null;
        $this->session = null;
        $this->cookies = [];
    }

    public function getSessionId(){
        return $this->session;
    }

    /** {@inheritDoc} */
    public function emit($event, array $args)
    {
        $namespace = $this->namespace;

        if ('' !== $namespace) {
            $namespace .= ',';
        }

        return $this->write(EngineInterface::MESSAGE, static::EVENT . $namespace . json_encode([$event, $args]));
    }

    /** {@inheritDoc} */
    public function of($namespace) {
        parent::of($namespace);

        $this->write(EngineInterface::MESSAGE, static::CONNECT . $namespace);
    }

    /** {@inheritDoc} */
    public function write($code, $message = null)
    {
        if (!is_resource($this->stream)) {
            return;
        }

        if (!is_int($code) || 0 > $code || 6 < $code) {
            throw new InvalidArgumentException('Wrong message type when trying to write on the socket');
        }

        $payload = new Encoder($code . $message, Encoder::OPCODE_TEXT, true);
        $bytes = fwrite($this->stream, (string) $payload);

        // wait a little bit of time after this message was sent
        usleep((int) $this->options['wait']);

        return $bytes;
    }

    /** {@inheritDoc} */
    public function getName()
    {
        return 'SocketIO Version 1.X';
    }

    /** {@inheritDoc} */
    protected function getDefaultOptions()
    {
        $defaults = parent::getDefaultOptions();

        $defaults['version']   = 2;
        $defaults['use_b64']   = false;
        $defaults['transport'] = static::TRANSPORT_POLLING;

        return $defaults;
    }

    /** Does the handshake with the Socket.io server and populates the `session` value object */
    protected function handshake()
    {
        if (null !== $this->session) {
            return;
        }

        $query = ['use_b64'   => $this->options['use_b64'],
                  'EIO'       => $this->options['version'],
                  'transport' => $this->options['transport']];

        if (isset($this->url['query'])) {
            $query = array_replace($query, $this->url['query']);
        }

        $context = $this->context;

        if (!isset($context[$this->url['secured'] ? 'ssl' : 'http'])) {
            $context[$this->url['secured'] ? 'ssl' : 'http'] = [];
        }

        $context[$this->url['secured'] ? 'ssl' : 'http']['timeout'] = (float) $this->options['timeout'];

        $url    = sprintf('%s://%s:%d/%s/?%s', $this->url['scheme'], $this->url['host'], $this->url['port'], trim($this->url['path'], '/'), http_build_query($query));
        $result = @file_get_contents($url, false, stream_context_create($context));

        if (false === $result) {
            throw new ServerConnectionFailureException;
        }

        $open_curly_at = strpos($result, '{');
        $todecode = substr($result, $open_curly_at, strrpos($result, '}')-$open_curly_at+1);
        $decoded = json_decode($todecode, true);

        if (!in_array('websocket', $decoded['upgrades'])) {
            throw new UnsupportedTransportException('websocket');
        }

        $cookies = [];
        foreach ($http_response_header as $header) {
            if (preg_match('/^Set-Cookie:\s*([^;]*)/i', $header, $matches)) {
                $cookies[] = $matches[1];
            }
        }
        $this->cookies = $cookies;

        $this->session = new Session($decoded['sid'], $decoded['pingInterval'], $decoded['pingTimeout'], $decoded['upgrades']);
    }

    /**
     * Upgrades the transport to WebSocket
     *
     * FYI:
     * Version "2" is used for the EIO param by socket.io v1
     * Version "3" is used by socket.io v2
     */
    protected function upgradeTransport()
    {
        $query = ['sid'       => $this->session->id,
                  'EIO'       => $this->options['version'],
                  'transport' => static::TRANSPORT_WEBSOCKET];

        if ($this->options['version'] === 2)
            $query['use_b64'] = $this->options['use_b64'];

        $url = sprintf('/%s/?%s', trim($this->url['path'], '/'), http_build_query($query));
        $hash = sha1(uniqid(mt_rand(), true), true);
        if ($this->options['version'] !== 2)
            $hash = substr($hash, 0, 16);
        $key = base64_encode($hash);

        $origin = '*';
        $headers = isset($this->context['headers']) ? (array) $this->context['headers'] : [] ;

        foreach ($headers as $header) {
            $matches = [];

            if (preg_match('`^Origin:\s*(.+?)$`', $header, $matches)) {
                $origin = $matches[1];
                break;
            }
        }

        $request = "GET {$url} HTTP/1.1\r\n"
                 . "Host: {$this->url['host']}:{$this->url['port']}\r\n"
                 . "Upgrade: WebSocket\r\n"
                 . "Connection: Upgrade\r\n"
                 . "Sec-WebSocket-Key: {$key}\r\n"
                 . "Sec-WebSocket-Version: 13\r\n"
                 . "Origin: {$origin}\r\n";

        if (!empty($this->cookies)) {
            $request .= "Cookie: " . implode('; ', $this->cookies) . "\r\n";
        }

        $request .= "\r\n";

        fwrite($this->stream, $request);
        $result = fread($this->stream, 12);

        if ('HTTP/1.1 101' !== $result) {
            throw new UnexpectedValueException(sprintf('The server returned an unexpected value. Expected "HTTP/1.1 101", had "%s"', $result));
        }

        // cleaning up the stream
        while ('' !== trim(fgets($this->stream)));

        $this->write(EngineInterface::UPGRADE);

        //remove message '40' from buffer, emmiting by socket.io after receiving EngineInterface::UPGRADE
        if ($this->options['version'] === 2)
            $this->read();
    }
}

// require_once __DIR__.'/Engine/SocketIO/Version2X.php';

class Version2X extends Version1X
{

    /** {@inheritDoc} */
    public function getName()
    {
        return 'SocketIO Version 2.X';
    }

    /** {@inheritDoc} */
    protected function getDefaultOptions()
    {
        $defaults = parent::getDefaultOptions();

        $defaults['version'] = 3;

        return $defaults;
    }
}


class NullLogger
{
  
    public function log($level, $message, array $context = array())
    {
        // noop
    }

    public function debug($msg){

    }
}

// require_once __DIR__.'/Client.php';

class Client
{
    /** @var EngineInterface */
    private $engine;

    /** @var LoggerInterface */
    private $logger;

    private $isConnected = false;

    public function __construct(EngineInterface $engine, LoggerInterface $logger = null)
    {
        $this->engine = $engine;
        $this->logger = $logger ?: new NullLogger;
    }

    public function __destruct()
    {
        if (!$this->isConnected) {
            return;
        }

        $this->close();
    }

    /**
     * Connects to the websocket
     *
     * @param boolean $keepAlive keep alive the connection (not supported yet) ?
     * @return $this
     */
    public function initialize($keepAlive = false)
    {
        try {
            $this->logger->debug('Connecting to the websocket');
            $this->engine->connect();
            $this->logger->debug('Connected to the server');

            $this->isConnected = true;

            if (true === $keepAlive) {
                $this->logger->debug('Keeping alive the connection to the websocket');
                $this->engine->keepAlive();
            }
        } catch (SocketException $e) {
            $this->logger->error('Could not connect to the server', ['exception' => $e]);

            throw $e;
        }

        return $this;
    }

    public function isConnected(){
        return $this->isConnected;
    }
    /**
     * Reads a message from the socket
     *
     * @return string Message read from the socket
     */
    public function read()
    {
        $this->logger->debug('Reading a new message from the socket');
        return $this->engine->read();
    }

    /**
     * Emits a message through the engine
     *
     * @param string $event
     * @param array  $args
     *
     * @return $this
     */
    public function emit($event, array $args)
    {
        $this->logger->debug('Sending a new message', ['event' => $event, 'args' => $args]);
        $this->engine->emit($event, $args);
        return $this;
    }

    /**
     * Sets the namespace for the next messages
     *
     * @param string namespace the name of the namespace
     * @return $this
     */
    public function of($namespace)
    {
        $this->logger->debug('Setting the namespace', ['namespace' => $namespace]);
        $this->engine->of($namespace);

        return $this;
    }

    /**
     * Closes the connection
     *
     * @return $this
     */
    public function close()
    {
        $this->logger->debug('Closing the connection to the websocket');
        $this->engine->close();

        $this->isConnected = false;

        return $this;
    }

    /**
     * Gets the engine used, for more advanced functions
     *
     * @return EngineInterface
     */
    public function getEngine()
    {
        return $this->engine;
    }
}

// require_once __DIR__.'/EngineInterface.php';

interface EngineInterface
{
    const OPEN    = 0;
    const CLOSE   = 1;
    const PING    = 2;
    const PONG    = 3;
    const MESSAGE = 4;
    const UPGRADE = 5;
    const NOOP    = 6;

    /** Connect to the targeted server */
    public function connect();

    /** Closes the connection to the websocket */
    public function close();

    /**
     * Read data from the socket
     *
     * @return string Data read from the socket
     */
    public function read();

    /**
     * Emits a message through the websocket
     *
     * @param string $event Event to emit
     * @param array  $args  Arguments to send
     */
    public function emit($event, array $args);

    /** Keeps alive the connection */
    public function keepAlive();

    /** Gets the name of the engine */
    public function getName();

    /** 
     * Sets the namespace for the next messages
     *
     * @param string $namespace the namespace
     */
    public function of($namespace);
}



// require_once __DIR__.'/AbstractPayload.php';

abstract class AbstractPayload
{
    const OPCODE_NON_CONTROL_RESERVED_1 = 0x3;
    const OPCODE_NON_CONTROL_RESERVED_2 = 0x4;
    const OPCODE_NON_CONTROL_RESERVED_3 = 0x5;
    const OPCODE_NON_CONTROL_RESERVED_4 = 0x6;
    const OPCODE_NON_CONTROL_RESERVED_5 = 0x7;

    const OPCODE_CONTINUE = 0x0;
    const OPCODE_TEXT     = 0x1;
    const OPCODE_BINARY   = 0x2;
    const OPCODE_CLOSE    = 0x8;
    const OPCODE_PING     = 0x9;
    const OPCODE_PONG     = 0xA;

    const OPCODE_CONTROL_RESERVED_1 = 0xB;
    const OPCODE_CONTROL_RESERVED_2 = 0xC;
    const OPCODE_CONTROL_RESERVED_3 = 0xD;
    const OPCODE_CONTROL_RESERVED_4 = 0xE;
    const OPCODE_CONTROL_RESERVED_5 = 0xF;

    protected $fin = 0b1; // only one frame is necessary
    protected $rsv = [0b0, 0b0, 0b0]; // rsv1, rsv2, rsv3

    protected $mask    = false;
    protected $maskKey = "\x00\x00\x00\x00";

    protected $opCode;

    /**
     * Mask a data according to the current mask key
     *
     * @param string $data Data to mask
     * @return string Masked data
     */
    protected function maskData($data)
    {
        $masked = '';
        $data   = str_split($data);
        $key    = str_split($this->maskKey);

        foreach ($data as $i => $letter) {
            $masked .= $letter ^ $key[$i % 4];
        }

        return $masked;
    }
}
