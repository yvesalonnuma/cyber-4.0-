"""
 HTTP Server Shell
 Author: Yves Alon Nums
 DATE: 1.1.26
 DESCRIPTION: http server that handle GET requests and responding to the client with the appropriate response (200,302,400,403,404,500)
"""
import socket
import logging

QUEUE_SIZE = 10
IP = '0.0.0.0'
PORT = 80
SOCKET_TIMEOUT = 2
READ_LEN = 1
PROTOCOL_VERSION = 'HTTP/1.1'
DEFAULT_URL = "/index.html"
WEBROOT = 'webroot'
VERB = 'GET'
OK_STATUS_CODE = 200
OK_TEXT = "OK"
MOVED_TEMPORARILY_STATUS_CODE = 302
MOVED_TEMPORARILY_TEXT = "MOVED TEMPORARILY"
BAD_REQUEST_STATUS_CODE = 400
BAD_REQUEST_TEXT = "BAD REQUEST"
FORBIDDEN_STATUS_CODE = 403
FORBIDDEN_STATUS_TEXT = "FORBIDDEN"
NOT_FOUND_STATUS_CODE = 404
NOT_FOUND_TEXT = "NOT FOUND"
INTERNAL_SERVER_ERROR_STATUS_CODE = 500
INTERNAL_SERVER_ERROR_TEXT = "ERROR"
READ_BINARY = 'rb'
READ = 'r'
END_OF_LINE = "\r\n"
END_OF_REQUEST = "\r\n\r\n"

REDIRECTION_DICTIONARY = {
    'moved': '/'
}

SHOULD_BE_ENCODES = ['html', 'txt', 'css', 'js']


def get_file_data(file_name):
    logger.debug(f"[FILE] Trying to read file: {file_name}")
    try:
        file_type = file_name.split('.')[-1]
        if file_type in SHOULD_BE_ENCODES:
            with open(file_name, READ) as f:
                file_data = f.read().encode()
        else:
            with open(file_name, READ_BINARY) as f:
                file_data = f.read()

        logger.info(f"[FILE] File loaded successfully ({len(file_data)} bytes)")
        return file_data

    except FileNotFoundError:
        logger.warning(f"[FILE] File not found: {file_name}")
        return None
    except Exception as e:
        logger.error(f"[FILE] Error reading file: {e}")
        return None


def build_response(code_status, status_text, headers, body=b''):
    logger.info(f"[RESPONSE] Building {code_status} {status_text}")

    response_line = PROTOCOL_VERSION + " " + str(code_status) + " " + status_text + END_OF_LINE
    header_lines = ""

    for key, value in headers.items():
        header_lines += key + ": " + value + END_OF_LINE
        logger.debug(f"[RESPONSE] Header {key}: {value}")

    header_lines += END_OF_LINE
    http_response = (response_line + header_lines).encode() + body

    logger.info(f"[RESPONSE] Total size: {len(http_response)} bytes")
    logging.info("Response headers: "+ response_line + header_lines)

    return http_response


def handle_client_request(resource, client_socket):
    logger.info(f"[REQUEST] Handling resource: {resource}")

    if resource == '/':
        resource = DEFAULT_URL

    if resource == '/forbidden':
        headers = {'Content-Length': '0'}
        response = build_response(FORBIDDEN_STATUS_CODE, FORBIDDEN_STATUS_TEXT, headers)
        client_socket.send(response)
        print("Sent 403 FORBIDDEN response")
        logger.warning("[RESPONSE] 403 FORBIDDEN sent")
        return

    if resource == '/error':
        headers = {'Content-Length': '0'}
        response = build_response(INTERNAL_SERVER_ERROR_STATUS_CODE, INTERNAL_SERVER_ERROR_TEXT, headers)
        client_socket.send(response)
        print("Sent 500 INTERNAL SERVER ERROR response")
        logger.error("[RESPONSE] 500 INTERNAL SERVER ERROR sent")
        return

    if resource in REDIRECTION_DICTIONARY:
        new_location = REDIRECTION_DICTIONARY[resource]
        headers = {'Location': new_location, 'Content-Length': '0'}
        response = build_response(MOVED_TEMPORARILY_STATUS_CODE, MOVED_TEMPORARILY_TEXT, headers)
        client_socket.send(response)
        print("Sent 302 MOVED TEMPORARILY response")
        logger.info(f"[RESPONSE] 302 Redirect to {new_location}")
        return

    uri = resource.lstrip('/')
    filename = WEBROOT + "\\" + uri

    data = get_file_data(filename)
    if data is None:
        headers = {'Content-Length': '0'}
        response = build_response(NOT_FOUND_STATUS_CODE, NOT_FOUND_TEXT, headers)
        client_socket.send(response)
        logger.warning("[RESPONSE] 404 NOT FOUND sent")
        return

    file_type = uri.split('.')[-1]
    headers = {
        'Content-Type': file_type,
        'Content-Length': str(len(data))
    }

    response = build_response(OK_STATUS_CODE, OK_TEXT, headers, data)
    client_socket.send(response)
    logger.info("[RESPONSE] 200 OK sent")


def validate_http_request(client_request):
    logger.debug(f"[REQUEST] Validating request: {client_request}")
    valid_request = False

    client_request_split = client_request.split(' ')
    requested_line = client_request_split[1]

    if client_request_split[0] == VERB and client_request_split[2] == PROTOCOL_VERSION:
        valid_request = True
    else:
        logger.warning("[REQUEST] Invalid HTTP request")

    return valid_request, requested_line


def handle_client(client_socket):
    print('Client connected')
    logger.info("[CLIENT] Client connected")

    try:
        headers = ""
        while not headers.endswith(END_OF_REQUEST):
            headers += client_socket.recv(READ_LEN).decode()

        print(headers)
        logger.debug(f"[CLIENT] Headers received:\n{headers}")

        client_request = headers.split(END_OF_LINE)[0]

    except socket.timeout:
        print('Client request timed out')
        logger.warning("[CLIENT] Request timeout")
        client_request = ""
    except Exception as e:
        print("something went wrong  " + str(e))
        logger.error(f"[CLIENT] Receive error: {e}")
        client_request = ""

    valid_http, resource = validate_http_request(client_request)

    if valid_http:
        print('Got a valid HTTP request')
        logger.info("[REQUEST] Valid HTTP request")
        handle_client_request(resource, client_socket)
    else:
        print('Error: Not a valid HTTP request')
        logger.warning("[REQUEST] Invalid HTTP request – sending 404")
        headers = {'Content-Length': '0'}
        response = build_response(NOT_FOUND_STATUS_CODE, NOT_FOUND_TEXT, headers)
        client_socket.send(response)
        print("Sent 404 NOT FOUND response")
        print('Closing connection')


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((IP, PORT))
        server_socket.listen(QUEUE_SIZE)
        print("Listening for connections on port %d" % PORT)
        logger.info(f"[SERVER] Listening on {IP}:{PORT}")

        while True:
            client_socket, client_address = server_socket.accept()
            print('New connection received')
            logger.info(f"[SERVER] New connection from {client_address}")

            try:
                client_socket.settimeout(SOCKET_TIMEOUT)
                handle_client(client_socket)
            except socket.error as err:
                print('received socket exception - ' + str(err))
                logger.exception("[SERVER] Socket error")
            finally:
                client_socket.close()
    except socket.error as err:
        print('received socket exception - ' + str(err))
        logger.exception("[SERVER] Fatal socket error")
    finally:
        server_socket.close()


if __name__ == "__main__":
    logging.basicConfig(
        filename="server.log",
        format="%(asctime)s | %(levelname)s | %(message)s",
        filemode="w"
    )
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    check_validation, check_requested_line = validate_http_request('GET / HTTP/1.1')
    assert check_validation is True, "didn't succeed validation"
    assert check_requested_line == '/', "didn't return the right requested line"

    data = get_file_data(WEBROOT + "\\" + DEFAULT_URL)
    assert data is not None, "didn't return the right data"

    check_response = build_response(FORBIDDEN_STATUS_CODE, FORBIDDEN_STATUS_TEXT,{'Content-Length': '0'})

    assert check_response == b'HTTP/1.1 403 FORBIDDEN\r\nContent-Length: 0\r\n\r\n',"didn't return the right response"
    print("all asserts passed")
    logging.info("all asserts passed")

    main()
