import { fromUrl } from 'parse-domain';

/**
 * check whether a uri is from "localhost" domain (i.e., from a server running locally, w/ respect to the user the uri came from)
 */
export const isLocalhost = (uri: string) => {
  const hostname = fromUrl(uri);
  return hostname === 'localhost'; // only consider `localhost`, not `127.0.0.1` or variants
};
