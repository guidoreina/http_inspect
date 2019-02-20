HTTP/HTTPS/DNS inspector
========================
`inspect` is a Windows driver which intercepts:
* HTTP and HTTPS (port 80 and 443, respectively):
  * The first outbound packet with payload of each connection.
  * The connection close.
* DNS responses (port 53).

And logs in a file:
* For HTTP:
  * Client IP address.
  * Server IP address.
  * URL.
* For HTTPS:
  * Client IP address.
  * Server IP address.
  * Hostname of the server (when the DNS response was seen).
* For DNS:
  * Client IP address.
  * Server IP address.
  * The hostname of the request.
  * The IP address of the response.
