import SAMPLES from './apiSamples.json'

export { SAMPLES }

const S = 'string'
const N = 'number'
const B = 'bool'
const L = 'list'
const O = 'object'

export const TEXT = {
  ref: 'API reference',
  refN: '{n} routes',
  base: 'Base URL',
  guide: [
    'Every request needs the header <b>Authorization: Bearer TOKEN</b>. Create the token above and turn external API access on.',
    'GET routes take their input in the query string, POST routes in a JSON body with <b>Content-Type: application/json</b>. GET routes also answer a POST with a JSON body.',
    'Every answer is JSON, all of its text is English, and it starts with the HTTP status in <b>code</b> — 200 on success. Every failure is an HTTP error (400, or 500 for a fault in the panel) with a stable name in <b>error</b> and an English explanation in <b>message</b> — a bot should decide on error, not on the text. Under each route are all the errors that route can return.',
    'Creating, editing, rebuilding, restarting and deleting a tunnel return an <b>act</b> at once and the work runs in the background. Read <b>/api/acts</b> until state goes from run to done or fail; a failed job has code (400, or 500 for a fault in the panel), error and message.',
    'Four routes work only from inside the panel and get 403 with a token: saving the settings, a new token, backup and restore.',
  ],
  search: 'Search routes…',
  empty: 'No route found',
  other: 'Other',
  deny: 'panel only',
  denyD: 'Does not work with a token and gets 403 — only from inside the panel, signed in.',
  pQuery: 'Input in the query string',
  pBody: 'Input in the JSON body',
  pNone: 'No input.',
  req: 'required',
  example: 'Example request',
  exampleBody: 'Example body',
  copy: 'Copy',
  answers: 'Responses',
  rowsAct: 'Every error a failure of this job can carry (next to state=fail):',
  rowsAll: 'Every error this route can return:',
  c: {
    200: 'Success',
    act: 'The job result in /api/acts — one finished and one failed sample',
    400: 'Invalid input or an action that did not happen',
    401: 'No token was sent, or the token is invalid',
    403: 'External API access is off, or this route is not allowed with a token',
    405: 'This route only accepts POST',
    413: 'The body is too large — a core binary up to 15 MB, a backup up to 32 MB, anything else up to 1 MB',
    429: 'After 8 failed attempts from one IP within 5 minutes (an invalid token, or a request while the API is off), that IP is locked until those 5 minutes end',
    500: "The panel's store (Redis) is unavailable or its data is damaged, or an internal error",
    503: 'The panel is busy — try again in a moment',
  },
}

export const GROUPS = [
  ['panel', 'Panel and dashboard', ['summary', 'readiness', 'ui-config', 'settings', 'settings-set', 'api-token-new', 'next-port']],
  [
    'nodes',
    'Nodes',
    [
      'nodes',
      'node-names',
      'node-add',
      'node-install',
      'install-status',
      'node-edit',
      'node-del',
      'node-toggle',
      'node-test',
      'node-stats',
      'node-ips',
      'traffic',
      'node-kernel-tune',
      'node-adopt-ip',
    ],
  ],
  [
    'links',
    'Tunnels',
    [
      'fleet',
      'create-tunnel',
      'edit-link',
      'rebuild-link',
      'link-rebuild-info',
      'restart-link',
      'delete-link',
      'link-toggle',
      'check-link',
      'link-speed',
      'link-view',
      'traffic-reset',
    ],
  ],
  ['pools', 'Edge and IP pools', ['edge-status', 'pool-retest-now', 'pool-select', 'peer-status', 'peer-retest-now', 'peer-select']],
  ['portfw', 'Port forwards', ['portfw-list', 'portfw', 'portfw-edit', 'portfw-next', 'portfw-del']],
  ['proxies', 'Proxies', ['proxies', 'proxy-add', 'proxy-edit', 'proxy-test', 'proxy-del']],
  [
    'updates',
    'Agent and core',
    [
      'agent-info',
      'agent-fetch-git',
      'agent-upload',
      'update-agent',
      'core-versions',
      'core-check',
      'core-stage',
      'core-stage-status',
      'core-stage-cancel',
      'core-upload',
      'core-delete-blob',
      'update-core',
      'push-status',
      'push-pause',
      'push-cancel',
    ],
  ],
  ['acts', 'Background jobs', ['acts', 'act-cancel']],
  ['order', 'Order and colour', ['reorder', 'link-tag']],
  ['logs', 'Log', ['events', 'events-clear']],
  ['backup', 'Backup', ['backup', 'backup-restore']],
]

const PROXY_REF = [
  ['proxy_on', 0, B, "reach the node's agent through a proxy"],
  ['proxy_id', 0, S, 'id of that proxy (from proxies) — required with proxy_on'],
]

const TUNNEL_FIELDS = [
  ['cipher', 0, S, 'auto, aes-256-gcm, aes-128-gcm, chacha20-poly1305, xchacha20-poly1305 or none (default auto)'],
  ['transport', 0, S, 'core carrier: udp, tcp, raw or ws (default udp)'],
  ['server_side', 0, S, 'a or b — which end listens (default a)'],
  ['obfs', 0, B, 'packet obfuscation — needs a cipher'],
  ['gso', 0, B, 'batched sending (GSO)'],
  ['cover', 0, B, 'TLS cover on the tcp carrier — needs cover_sni'],
  ['cover_sni', 0, S, 'cover domain of the TLS cover'],
  ['raw_profile', 0, S, 'raw profile: bare, ipip, gre, icmp, udp, tcp, esp, ah, etherip, ipcomp or l2tpv3'],
  ['raw_proto', 0, N, 'IP protocol number — bare profile only'],
  ['raw_port', 0, N, 'carrier port (1 to 65535) — udp and tcp profiles only'],
  ['raw_sport', 0, N, 'fixed source port — udp and tcp profiles only'],
  ['raw_sport_random', 0, B, 'random source port instead of a fixed one — not together with raw_sport'],
  ['raw_sport_rotate', 0, N, 'a fresh source port every few packets (1 to 60)'],
  ['raw_dports', 0, N, 'number of destination ports (1 to 16) — only with raw_sport_rotate'],
  ['conntrack_bypass', 0, B, 'bypass the conntrack table — udp and tcp profiles only'],
  ['sport_lo', 0, N, 'start of the source port band (1024 and up)'],
  ['sport_hi', 0, N, 'end of the source port band — the band is at least 100 ports wide'],
  ['port_tries', 0, N, 'number of source port draws (1 to 60)'],
  ['fec', 0, B, 'forward error correction — udp and raw only'],
  ['fec_data', 0, N, 'data packets per FEC group (default 16, at most 64)'],
  ['fec_parity', 0, N, 'parity packets (default 4; data plus parity at most 255)'],
  ['a_workers', 0, N, 'parallel queues on end a (1 to 8) — udp and raw without FEC only'],
  ['b_workers', 0, N, 'parallel queues on end b (1 to 8)'],
  ['fake_desync', 0, B, 'send decoy packets before the handshake — raw, tcp and ws'],
  ['fake_ttl', 0, N, 'decoy TTL (default 4)'],
  ['fake_count', 0, N, 'number of decoys (1 to 64, default 2)'],
  ['fake_mode', 0, S, 'ttl, badsum or both'],
  ['ip_rotate', 0, B, 'rotate between several node IPs — udp, tcp and raw'],
  ['a_ip_pool', 0, L, 'IPs of end a to rotate over'],
  ['b_ip_pool', 0, L, 'IPs of end b to rotate over'],
  ['rotate_secs', 0, N, 'IP rotation interval in seconds'],
  ['cdn_carrier', 0, S, 'CDN carrier on ws: ws, http or grpc (grpc needs ws_tls)'],
  ['ws_host', 0, S, 'CDN domain'],
  ['ws_path', 0, S, 'WebSocket path — starts with /'],
  ['ws_tls', 0, B, 'wss (TLS up to the CDN edge) — needs ws_host and edge_ip'],
  ['edge_ip', 0, S, 'CDN edge IP, with or without a port'],
  ['ech', 0, B, 'Encrypted ClientHello — needs ws_tls'],
  ['ech_proxy', 0, B, 'fetch the ECH key through a proxy'],
  ['ech_proxy_id', 0, S, 'id of that proxy'],
  ['http_up_workers', 0, N, 'http carrier: number of upload channels (1 to 16)'],
  ['http_up_batch_kb', 0, N, 'http carrier: batch size in KB (8 to 512)'],
  ['http_up_rate', 0, N, 'http carrier: upload rate cap (0 to 1000; 0 = no cap)'],
  ['http_streams', 0, N, 'http and grpc carriers: number of streams (1 to 16)'],
  ['sni_split', 0, B, 'split the SNI in the ClientHello — needs ws_tls'],
  ['split_pos', 0, N, 'split point (0 to 1400; 0 = the middle of the domain)'],
  ['sni_mode', 0, S, 'split, disorder or fake'],
  ['split_ttl', 0, N, 'TTL of the first segment in disorder mode'],
  ['ws_pool', 0, B, 'edge pool: rotate over several edge IPs and domains'],
  ['ws_edge_ips', 0, L, 'edge IPs as IPv4:port (at most 64)'],
  ['ws_edge_snis', 0, L, 'domains; each item is a domain or {"host", "path"} (at most 64)'],
  ['ws_rotate_secs', 0, N, 'edge rotation interval in seconds (default 600)'],
  ['ws_port_roll', 0, B, 'a fresh source port on every edge rotation'],
]

export const DOCS = {
  summary: {
    t: 'Dashboard summary',
    d: "Node and tunnel counts, the health score, the panel's own resource use, alerts and the number of unread log events — what the overview page shows.",
    p: [['seen', 0, S, 'id of the last log event you saw; unread is counted after it']],
  },
  readiness: {
    t: 'Agent and core readiness',
    d: 'Whether the agent and the core are ready on the panel to reach the nodes, and if not, which core architecture is missing.',
  },
  'ui-config': {
    t: 'User interface configuration',
    d: 'Fixed values the user interface needs: tuning defaults and ranges, event types, tunnel form options, and the list of these API routes with the method of each.',
  },
  settings: {
    t: 'Read the settings',
    d: 'All panel settings. The API token hash is not in the answer.',
  },
  'settings-set': {
    t: 'Save the settings',
    d: 'Only the keys you send change, and the answer is the full new settings. A number outside its range is clamped to the allowed limit.',
    p: [
      ['reconcile_mode', 0, S, 'auto (repair by itself) or alert (only warn)'],
      ['reconcile_interval', 0, N, 'repair check interval in seconds (5 to 3600)'],
      ['poll_interval', 0, N, 'node poll interval in seconds (0.3 to 60)'],
      ['ui_interval', 0, N, 'screen refresh interval in seconds (0.3 to 60)'],
      ['uptime_window', 0, N, 'uptime chart window in hours: 1, 3, 6, 8, 12 or 24'],
      ['ech_refresh_mins', 0, N, 'ECH key refresh in minutes (0 = off, 1 to 1440)'],
      ['agent_delivery', 0, S, 'agent delivery: push, github or panel'],
      ['core_delivery', 0, S, 'core delivery: push, github or panel'],
      ['api_external', 0, B, 'turn API access with a token on or off'],
      ['dl_proxy_on', 0, B, 'download from GitHub through a proxy'],
      ['dl_proxy_id', 0, S, 'id of that proxy'],
      ['log_hidden', 0, L, 'event types hidden from the log'],
      ['tuning', 0, O, 'tuning values; keys and ranges are in ui-config'],
    ],
  },
  'api-token-new': {
    t: 'Create a new token',
    d: 'Creates a new token and shows it only this once. The previous token stops working at that moment.',
  },
  'next-port': {
    t: 'Suggest a free port',
    d: 'A random port from 20000 to 29999 that no tunnel uses — for the port field when creating a tunnel.',
  },

  nodes: {
    t: 'List the nodes',
    d: 'Every node with its state, uptime, traffic, proxy, and agent and core versions.',
    p: [['q', 0, S, 'search in the name and the address']],
  },
  'node-names': {
    t: 'Light node list',
    d: 'Id, name, address, online state and IPs of every node — for picking a node in forms.',
    p: [['q', 0, S, 'search in the name and the address']],
  },
  'node-add': {
    t: 'Add a node',
    d: 'Adds a node whose agent is already installed. The panel connects to it in the background; read its state from nodes.',
    p: [
      ['name', 1, S, 'unique name: Latin letters, digits, space and _ . -, up to 40 characters'],
      ['host', 1, S, "the node's IP or domain"],
      ['port', 1, N, 'agent port (usually 8099)'],
      ['token', 1, S, 'agent token, at least 16 characters'],
      ...PROXY_REF,
    ],
  },
  'node-install': {
    t: 'Install the agent over SSH',
    d: 'Installs the agent on the server over SSH and adds the node. The work runs in the background; read its progress with install-status and that job.',
    p: [
      ['name', 1, S, 'unique node name'],
      ['ssh_host', 1, S, "the server's IP or domain"],
      ['ssh_port', 0, N, 'SSH port (default 22)'],
      ['ssh_user', 0, S, 'SSH user (default root)'],
      ['ssh_pass', 0, S, 'SSH password — this or ssh_key is required'],
      ['ssh_key', 0, S, 'the full text of the private key'],
      ['agent_port', 0, N, 'port the agent listens on (default 8099)'],
      ...PROXY_REF,
    ],
  },
  'install-status': {
    t: 'Install progress',
    d: 'The steps of an install started by node-install, whether it finished, and the result.',
    p: [['job', 1, S, 'job id from the node-install answer']],
  },
  'node-edit': {
    t: 'Edit a node',
    d: "Changes the node's name, address, port, token or proxy.",
    p: [
      ['id', 1, S, 'node id'],
      ['name', 1, S, 'unique name'],
      ['host', 1, S, 'IP or domain'],
      ['port', 1, N, 'agent port'],
      ['token', 0, S, 'new agent token; empty = keep the current one'],
      ...PROXY_REF,
    ],
  },
  'node-del': {
    t: 'Delete a node',
    d: 'Deletes the node and all of its tunnels. The node is cleaned first, and if it does not answer, nothing is deleted.',
    p: [
      ['id', 1, S, 'node id'],
      ['force', 0, B, 'if the panel has confirmed the node is down, delete it from the panel without cleaning the node'],
    ],
  },
  'node-toggle': {
    t: 'Hide a node',
    d: 'Hides the node from the node picker when creating a tunnel, or shows it again.',
    p: [
      ['id', 1, S, 'node id'],
      ['disabled', 0, B, 'true = hide, false = show'],
    ],
  },
  'node-test': {
    t: 'Test the connection to a node',
    d: "Asks the node's agent right now: version, IPs, readiness and the panel address it knows.",
    p: [['id', 1, S, 'node id']],
  },
  'node-stats': {
    t: 'Node resources',
    d: "CPU, RAM, disk, load, operating system and network interfaces of the node from the last poll.",
    p: [['id', 1, S, 'node id']],
  },
  'node-ips': {
    t: 'Node IPs',
    d: "The node's IPs and which tunnel or port forward sits on each.",
    p: [['id', 1, S, 'node id']],
  },
  traffic: {
    t: 'Node traffic',
    d: 'Speed and volume of the traffic of the whole node, each tunnel and each port forward on it.',
    p: [['id', 1, S, 'node id']],
  },
  'node-kernel-tune': {
    t: 'Node kernel tuning',
    d: "Reads the node's BBR and network queue state, or turns the tuning on or off.",
    p: [
      ['id', 1, S, 'node id'],
      ['action', 0, S, 'status (default), apply or revert'],
    ],
  },
  'node-adopt-ip': {
    t: "Adopt the node's new address",
    d: "When the node reported another address (moved_to in nodes), makes that address the node's address.",
    p: [['id', 1, S, 'node id']],
  },

  fleet: {
    t: 'List the tunnels',
    d: 'Tunnels with the health of both ends and live traffic.',
    p: [
      ['kind', 0, S, 'core = core tunnels only, tunnels = system tunnels only; empty = all'],
      ['q', 0, S, 'search'],
    ],
  },
  'create-tunnel': {
    t: 'Create a tunnel',
    act: true,
    d: 'Creates a tunnel between two nodes. The answer comes at once with only the job id; read the result (or the input error) from acts with that act. The core fields are read only when type=core.',
    p: [
      ['a_node', 1, S, 'node id of end a'],
      ['b_node', 1, S, 'node id of end b'],
      ['type', 1, S, 'core, vxlan, gre, sit, ipip, l2tpv3, fou or ipsec'],
      ['a_ip', 0, S, 'which IP of node a (default the first IP)'],
      ['b_ip', 0, S, 'which IP of node b'],
      ['subnet_base', 0, S, '192.168 (default), 172.16 or 10 — the subnet is picked from this range'],
      ['subnet', 0, S, 'manual subnet with a prefix, for example 192.168.9.0/24'],
      ['id', 0, N, 'manual tunnel id; empty = the first free id'],
      ['port', 0, N, 'tunnel port; empty = automatic (vxlan: 4789)'],
      ...TUNNEL_FIELDS,
    ],
  },
  'edit-link': {
    t: 'Edit a tunnel',
    act: true,
    d: 'Rebuilds the tunnel on both ends with the new values. A field you do not send keeps its current value if it fits the new shape of the tunnel. Read the result from acts.',
    p: [
      ['id', 1, S, 'tunnel id'],
      ['type', 1, S, 'tunnel type; if it differs from the current type, the tunnel is built with the new type'],
      ['a_node', 0, S, 'new node of end a'],
      ['b_node', 0, S, 'new node of end b'],
      ['a_ip', 0, S, 'new IP of end a'],
      ['b_ip', 0, S, 'new IP of end b'],
      ['subnet', 0, S, 'new subnet'],
      ['port', 0, N, 'new port; not sent = keep the current one, empty = automatic'],
      ...TUNNEL_FIELDS,
    ],
  },
  'rebuild-link': {
    t: 'Rebuild a tunnel',
    act: true,
    d: 'Rebuilds the tunnel on both ends with the saved settings — for when one end lost something. Read the result from acts.',
    p: [
      ['id', 1, S, 'tunnel id'],
      ['a_ip', 0, S, 'another IP of node a (from link-rebuild-info)'],
      ['b_ip', 0, S, 'another IP of node b'],
      ['pin', 0, B, 'false = the new IP is not saved and the tunnel is marked as "IP changed" (default true)'],
    ],
  },
  'link-rebuild-info': {
    t: 'IPs to pick for a rebuild',
    d: 'For each end of the tunnel: whether it is online, whether the saved IP is still on the node, and the IPs it has.',
    p: [['id', 1, S, 'tunnel id']],
  },
  'restart-link': {
    t: 'Restart a tunnel',
    act: true,
    d: 'Restarts the tunnel on both ends. Read the result from acts.',
    p: [['id', 1, S, 'tunnel id']],
  },
  'delete-link': {
    t: 'Delete a tunnel',
    act: true,
    d: 'Deletes the tunnel from both ends and from the panel. If one end is down the job ends with offer=force and nothing is deleted; then send it again with force=true.',
    p: [
      ['id', 1, S, 'tunnel id'],
      ['force', 0, B, 'delete even if one end is down'],
    ],
  },
  'link-toggle': {
    t: 'Turn a tunnel on or off',
    d: 'Turns the tunnel on or off on both ends. If one end fails, the other end goes back to its previous state.',
    p: [
      ['id', 1, S, 'tunnel id'],
      ['enabled', 0, B, 'true = on, false = off'],
    ],
  },
  'check-link': {
    t: 'Check tunnel health',
    d: 'Gets the health of both ends right now: up or not, latency and packet loss.',
    p: [['id', 1, S, 'tunnel id']],
  },
  'link-speed': {
    t: 'Tunnel speed test',
    d: 'Measures the upload and download speed inside the tunnel for a few seconds and returns it in megabits.',
    p: [['id', 1, S, 'tunnel id']],
  },
  'link-view': {
    t: 'Switch the viewed end',
    d: "Switches the end whose view of the tunnel's traffic is shown between a and b.",
    p: [['id', 1, S, 'tunnel id']],
  },
  'traffic-reset': {
    t: 'Reset a traffic counter',
    d: 'Resets the volume counter of a tunnel, a node, or a port forward on that node. One of id or node is required.',
    p: [
      ['id', 0, S, 'tunnel id'],
      ['node', 0, S, 'node id'],
      ['name', 0, S, 'port forward name on that node; empty = the whole node'],
    ],
  },

  'edge-status': {
    t: 'Edge status',
    d: 'For a core tunnel: the active path, and if it has an edge pool, the health of every edge IP and domain and the recent events.',
    p: [['id', 1, S, 'tunnel id']],
  },
  'pool-retest-now': {
    t: 'Retest an edge pool member',
    d: 'Tests an IP or a domain of the edge pool again right now.',
    p: [
      ['id', 1, S, 'tunnel id'],
      ['kind', 1, S, 'ip or sni'],
      ['key', 1, S, 'that IP:port or domain'],
    ],
  },
  'pool-select': {
    t: 'Pick an edge pool member',
    d: 'Moves the tunnel to a given IP or domain of the edge pool.',
    p: [
      ['id', 1, S, 'tunnel id'],
      ['kind', 1, S, 'ip or sni'],
      ['key', 1, S, 'that IP:port or domain'],
    ],
  },
  'peer-status': {
    t: 'IP pool status',
    d: 'For a tunnel with IP rotation: the active address and the health of every destination and source IP.',
    p: [['id', 1, S, 'tunnel id']],
  },
  'peer-retest-now': {
    t: 'Retest an IP',
    d: 'Tests an IP of the rotation pool again right now.',
    p: [
      ['id', 1, S, 'tunnel id'],
      ['kind', 1, S, 'dst (destination) or src (source)'],
      ['key', 1, S, 'that IP'],
    ],
  },
  'peer-select': {
    t: 'Pick an IP',
    d: 'Moves the tunnel to a given IP of the rotation pool.',
    p: [
      ['id', 1, S, 'tunnel id'],
      ['key', 1, S, 'that IP'],
      ['side', 0, S, 'dst (default) or src'],
    ],
  },

  'portfw-list': {
    t: 'List the port forwards',
    d: 'Every port forward on every node with its active destination and traffic.',
    p: [['q', 0, S, 'search in the node name, the ports and the IPs']],
  },
  portfw: {
    t: 'Create a port forward',
    d: "Sends the traffic of a node port to one or more destination IPs. The answer has the created name.",
    p: [
      ['node', 1, S, 'node id'],
      ['listen_port', 1, N, 'listen port on the node'],
      ['dst_port', 1, N, 'destination port'],
      ['dst_ips', 1, L, 'destination IPs — an array or a comma-separated string'],
      ['rotate', 0, B, 'rotate between the destinations'],
      ['interval_min', 0, N, 'rotation interval in minutes (1 to 1440) — required with rotate'],
      ['iface', 0, S, 'network interface'],
      ['listen_ip', 0, S, 'listen only on this node IP'],
    ],
  },
  'portfw-edit': {
    t: 'Edit a port forward',
    d: 'Only the fields you send change. An empty listen_ip means all IPs.',
    p: [
      ['node', 1, S, 'node id'],
      ['name', 1, S, 'port forward name'],
      ['listen_port', 0, N, 'listen port'],
      ['dst_port', 0, N, 'destination port'],
      ['dst_ips', 0, L, 'destination IPs'],
      ['rotate', 0, B, 'rotate between the destinations'],
      ['interval_min', 0, N, 'rotation interval in minutes'],
      ['iface', 0, S, 'network interface'],
      ['listen_ip', 0, S, 'listen IP'],
    ],
  },
  'portfw-next': {
    t: 'Go to the next destination',
    d: 'Switches the active destination to the next one right now — at least two destinations are needed.',
    p: [
      ['node', 1, S, 'node id'],
      ['name', 1, S, 'port forward name'],
    ],
  },
  'portfw-del': {
    t: 'Delete a port forward',
    d: 'Deletes the port forward from the node.',
    p: [
      ['node', 1, S, 'node id'],
      ['name', 1, S, 'port forward name'],
    ],
  },

  proxies: {
    t: 'List the proxies',
    d: 'Proxies with their state and the nodes and tunnels that use them. The password is never returned (only has_pass).',
  },
  'proxy-add': {
    t: 'Add a proxy',
    d: 'Adds a socks5 or http proxy.',
    p: [
      ['name', 1, S, 'unique name, up to 40 characters'],
      ['host', 1, S, 'IP or domain'],
      ['port', 1, N, 'port (1 to 65535)'],
      ['scheme', 0, S, 'socks5 (default) or http'],
      ['user', 0, S, 'username'],
      ['pass', 0, S, 'password'],
    ],
  },
  'proxy-edit': {
    t: 'Edit a proxy',
    d: 'Changes the proxy and can give it to nodes or take it from them.',
    p: [
      ['id', 1, S, 'proxy id'],
      ['name', 1, S, 'unique name'],
      ['host', 1, S, 'IP or domain'],
      ['port', 1, N, 'port'],
      ['scheme', 0, S, 'socks5 or http'],
      ['user', 0, S, 'username'],
      ['pass', 0, S, 'new password; empty = keep the current one (with an empty user the password is cleared too)'],
      ['nodes_on', 0, L, 'ids of nodes that should use this proxy'],
      ['nodes_off', 0, L, 'ids of nodes that should stop using it'],
    ],
  },
  'proxy-test': {
    t: 'Test a proxy',
    d: 'Connects from the panel to the proxy right now. A broken proxy answers 400 with the error and message of the failure.',
    p: [['id', 1, S, 'proxy id']],
  },
  'proxy-del': {
    t: 'Delete a proxy',
    d: 'Deletes the proxy.',
    p: [['id', 1, S, 'proxy id']],
  },

  'agent-info': {
    t: 'Agent ready on the panel',
    d: 'Version, sha256, size and source of the agent file the panel delivers to the nodes.',
  },
  'agent-fetch-git': {
    t: 'Fetch the agent from GitHub',
    d: "Fetches the agent's latest release from GitHub, checks its checksum and makes it ready on the panel.",
  },
  'agent-upload': {
    t: 'Upload an agent file',
    d: 'Puts a tnl-node.py file in place of the agent ready on the panel.',
    p: [['code', 1, S, 'the full text of the tnl-node.py file']],
  },
  'update-agent': {
    t: "Update the nodes' agent",
    d: 'Delivers the ready agent to the chosen nodes. The work runs in the background; read the progress from push-status.',
    p: [['ids', 1, L, 'node ids']],
  },
  'core-versions': {
    t: 'Core versions',
    d: 'The core versions on GitHub and the version ready on the panel.',
  },
  'core-check': {
    t: 'Check for a new core version',
    d: 'Refreshes the version list from GitHub and tells whether a newer version came out. A GitHub error answers 400.',
  },
  'core-stage': {
    t: 'Make a core ready on the panel',
    d: 'Downloads a core version from GitHub to the panel. Read the progress from core-stage-status. If the core delivery mode is github, only its details are fetched.',
    p: [['version', 0, S, 'version tag, for example v2.136.0 (default latest)']],
  },
  'core-stage-status': {
    t: 'Core download progress',
    d: 'Percent, whether it finished and the fetched architectures of a download started by core-stage; a failed or cancelled download answers 400 with error and message.',
  },
  'core-stage-cancel': {
    t: 'Cancel the core download',
    d: 'Stops the running core download.',
  },
  'core-upload': {
    t: 'Upload a core binary',
    d: 'Puts a custom core binary on the panel (at most 15 MB). It reaches the nodes with update-core and version=custom.',
    p: [
      ['data', 1, S, 'the binary in base64'],
      ['name', 0, S, 'file name'],
    ],
  },
  'core-delete-blob': {
    t: 'Delete the custom binary',
    d: 'Deletes the core binary uploaded with core-upload.',
  },
  'update-core': {
    t: "Update the nodes' core",
    d: 'Installs the core on the chosen nodes. The work runs in the background; read the progress from push-status.',
    p: [
      ['ids', 1, L, 'node ids'],
      ['version', 0, S, 'empty = the version ready on the panel, a tag like v2.136.0, or custom for the uploaded binary'],
    ],
  },
  'push-status': {
    t: 'Node update progress',
    d: 'The state of every node in an agent or core update; a failed node has its code in err and the reason in detail.',
    p: [['job', 0, S, 'job id; empty = all running jobs']],
  },
  'push-pause': {
    t: 'Pause or resume an update',
    d: 'Holds the queued nodes or starts them again; a node that has started runs to the end.',
    p: [
      ['job', 0, S, 'job id; empty = all'],
      ['paused', 0, B, 'true (default) = pause, false = resume'],
    ],
  },
  'push-cancel': {
    t: 'Cancel an update',
    d: 'Nodes still in the queue are left out of the update.',
    p: [['job', 0, S, 'job id; empty = all']],
  },

  acts: {
    t: 'Background jobs',
    d: 'The state of tunnel create, edit, rebuild, restart and delete jobs: state is one of run, done, fail or cancel; a failed job has code (400, or 500 for a fault in the panel), error and message.',
  },
  'act-cancel': {
    t: 'Cancel a background job',
    d: 'Cancels a job that has not reached its point of no return.',
    p: [['act', 1, S, 'job id from the answer of create-tunnel and the like']],
  },

  reorder: {
    t: 'Change the order',
    d: 'Swaps item id with each of targets in turn — the same as dragging and dropping the cards.',
    p: [
      ['kind', 1, S, 'nodes, core, tunnels or portfw'],
      ['id', 1, S, 'id of the item that moves'],
      ['targets', 1, L, 'ids of the items it swaps places with (at most 256)'],
    ],
  },
  'link-tag': {
    t: 'Tag colour',
    d: "Gives a tunnel's or a node's card a tag colour.",
    p: [
      ['id', 1, S, 'tunnel or node id'],
      ['tag', 0, N, '0 to 6; 0 = no colour'],
    ],
  },

  events: {
    t: 'Log',
    d: 'The events of the last 24 hours, except the types hidden in the settings. The text of each event is in text and its details in detail.',
  },
  'events-clear': {
    t: 'Clear the log',
    d: 'Deletes every event.',
  },

  backup: {
    t: 'Take a backup',
    d: "Returns all panel data and the signing key compressed and in base64 in data, with the counts of nodes, tunnels and proxies.",
  },
  'backup-restore': {
    t: 'Restore a backup',
    d: 'Without apply it only reads the file and returns the comparison with the current state. With apply=true the data is replaced and the panel restarts by itself (restarting=true in the answer).',
    p: [
      ['data', 1, S, 'the backup file in base64 (at most 32 MB)'],
      ['apply', 0, B, 'true = really restore'],
    ],
  },
}
