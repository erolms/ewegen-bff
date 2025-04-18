/**
 * Normalize a port into a number, string, or false.
 * @param val - The port value to normalize
 * @returns A number, string, or false
 */
export function normalizePort(val: string): string | number | false {
  const port = parseInt(val, 10);

  if (isNaN(port)) {
    // named pipe
    return val;
  }

  if (port >= 0) {
    // port number
    return port;
  }

  return false;
}
