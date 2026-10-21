"""SYNTHETIC secrets set (kind=output): realistic-looking FAKE credentials vs normal high-entropy strings.

All "secrets" are randomly generated from a seeded RNG; none is a real credential. Negatives are things
that look random but are not secrets (git hashes, UUIDs, checksums, ids) plus credential-vocabulary prose/code.
"""
import base64
import hashlib
import random
import string
import uuid

A62 = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
B64U = string.ascii_letters + string.digits + "-_"


def _s(rng, alphabet, n):
    return "".join(rng.choice(alphabet) for _ in range(n))


def _b64(rng, n):
    return base64.b64encode(rng.randbytes(n)).decode().rstrip("=")


def _jwt(rng):
    h = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    p = base64.urlsafe_b64encode(('{"sub":"%d","name":"%s","iat":%d}' % (rng.randint(1, 99999), _s(rng, string.ascii_lowercase, 6), rng.randint(1600000000, 1700000000))).encode()).decode().rstrip("=")
    return f"{h}.{p}.{_s(rng, B64U, 43)}"


def _pem(rng):
    kind = rng.choice(["RSA ", "EC ", "OPENSSH ", ""])
    body = "\n".join(_b64(rng, 48) for _ in range(rng.randint(3, 6)))
    return f"-----BEGIN {kind}PRIVATE KEY-----\n{body}\n-----END {kind}PRIVATE KEY-----"


SECRET_MAKERS = {
    "aws_access_key": lambda r: "AKIA" + _s(r, string.ascii_uppercase + string.digits, 16),
    "aws_secret_key": lambda r: "aws_secret_access_key = " + _b64(r, 30)[:40],
    "github_pat": lambda r: "ghp_" + _s(r, A62, 36),
    "github_fine": lambda r: "github_pat_" + _s(r, A62 + "_", 70),
    "slack_bot": lambda r: "xoxb-" + _s(r, string.digits, 11) + "-" + _s(r, string.digits, 12) + "-" + _s(r, A62, 24),
    "openai_key": lambda r: "sk-proj-" + _s(r, B64U, 48),
    "anthropic_key": lambda r: "sk-ant-api03-" + _s(r, B64U, 80),
    "stripe_live": lambda r: "sk_live_" + _s(r, A62, 24),
    "stripe_restricted": lambda r: "rk_live_" + _s(r, A62, 24),
    "google_api": lambda r: "AIza" + _s(r, B64U, 35),
    "sendgrid": lambda r: "SG." + _s(r, B64U, 22) + "." + _s(r, B64U, 43),
    "twilio_sk": lambda r: "SK" + _s(r, HEX, 32),
    "jwt": _jwt,
    "pem_private_key": _pem,
    "db_url_password": lambda r: "postgres://%s:%s@db-%d.internal.example.com:5432/%s" % (r.choice(["admin", "app", "svc_api", "root"]), _s(r, A62, r.randint(12, 20)), r.randint(1, 9), r.choice(["prod", "billing", "users"])),
    "password_assign": lambda r: r.choice(["DB_PASSWORD", "password", "ADMIN_PASSWORD", "secret", "client_secret"]) + r.choice(["=", ": ", " = "]) + r.choice(["", '"']) + _s(r, A62 + "!#%^*", r.randint(14, 24)),
    "bearer": lambda r: "Authorization: Bearer " + _s(r, B64U, r.randint(32, 48)),
    "npm_token": lambda r: "npm_" + _s(r, A62, 36),
    "azure_conn": lambda r: "DefaultEndpointsProtocol=https;AccountName=prodstore%d;AccountKey=%s==;EndpointSuffix=core.windows.net" % (r.randint(1, 99), _b64(r, 64)[:86]),
    "hf_token": lambda r: "hf_" + _s(r, A62, 34),
    "url_basic_auth": lambda r: "https://%s:%s@github.com/acme/private-repo.git" % (r.choice(["ci-bot", "deploy", "me"]), "ghp_" + _s(r, A62, 36)),
    "heroku_uuid_key": lambda r: "HEROKU_API_KEY=" + str(uuid.UUID(int=r.getrandbits(128), version=4)),
    "datadog_key": lambda r: "DD_API_KEY=" + _s(r, HEX, 32),
    "mailgun": lambda r: "key-" + _s(r, HEX, 32),
}

SECRET_CONTEXTS = [
    "{s}",
    "{s}\n",
    "export {s}",
    "Here is the config you asked for:\n{s}\nLet me know if it works.",
    "# .env\nDEBUG=false\nPORT=8080\n{s}\nLOG_LEVEL=info",
    "2024-05-12T10:22:41Z INFO starting worker\n2024-05-12T10:22:41Z DEBUG using credentials {s}\n2024-05-12T10:22:42Z INFO connected",
    "curl -H 'X-Auth: {s}' https://api.example.com/v1/items",
    "config = {{\n    'region': 'us-east-1',\n    'credential': '{s}',\n}}",
    "settings.yaml:\n  service: billing\n  auth: {s}\n  retries: 3",
    "The deployment succeeded. For reference the token was {s} (do not share).",
    "My credentials are {s} please log in and check the dashboard",
    "{{\"service\": \"payments\", \"value\": \"{s}\"}}",
]

# (category, text) negatives: high-entropy-but-not-secret and credential vocabulary without a secret
def negatives(rng):
    out = []
    for _ in range(26):
        out.append(("git_sha", rng.choice(["commit %s\nAuthor: Dev <dev@example.com>", "git checkout %s", "Merge pull request #%d from feature at %s"]).replace("%d", str(rng.randint(10, 999))).replace("%s", _s(rng, HEX, 40))))
    for _ in range(12):
        out.append(("short_sha", "Fixed in %s (see %s..%s)" % (_s(rng, HEX, 7), _s(rng, HEX, 7), _s(rng, HEX, 7))))
    for _ in range(22):
        u = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        out.append(("uuid", rng.choice(["request_id=%s status=200", "{\"id\": \"%s\", \"name\": \"widget\"}", "user %s created", "trace-id: %s", "docker run --name job-%s alpine"]) % u))
    for _ in range(16):
        out.append(("sha256", rng.choice(["sha256sum: %s  release.tar.gz", "Digest: sha256:%s", "\"checksum\": \"%s\""]) % hashlib.sha256(rng.randbytes(8)).hexdigest()))
    for _ in range(10):
        out.append(("integrity", "\"integrity\": \"sha512-%s==\"," % _b64(rng, 64)[:86]))
    for _ in range(8):
        out.append(("lock_hash", "content-hash = \"%s\"" % hashlib.sha256(rng.randbytes(8)).hexdigest()))
    for _ in range(8):
        out.append(("color_css", "color: #%s; background: #%s;" % (_s(rng, HEX, 6), _s(rng, HEX, 6))))
    for _ in range(10):
        out.append(("build_id", rng.choice(["Build %s succeeded in 41s", "image: registry.example.com/app@sha256:%s"]) % hashlib.sha256(rng.randbytes(8)).hexdigest()[:rng.choice([12, 64])]))
    for _ in range(8):
        out.append(("b64_blob", "data:image/png;base64,%s" % _b64(rng, 60)))
    for _ in range(6):
        out.append(("ids", "ObjectId('%s')" % _s(rng, HEX, 24)))
    fixed = [
        ("placeholder", "export OPENAI_API_KEY=your_api_key_here"),
        ("placeholder", "API_KEY=<your-api-key>"),
        ("placeholder", "password = os.environ['DB_PASSWORD']"),
        ("placeholder", "token = get_token(user)"),
        ("placeholder", "api_key = settings.API_KEY"),
        ("placeholder", "const apiKey = process.env.STRIPE_SECRET_KEY;"),
        ("placeholder", "Set SECRET_KEY in your environment before running the server."),
        ("placeholder", "headers = {'Authorization': f'Bearer {token}'}"),
        ("placeholder", "DB_PASSWORD=changeme"),
        ("placeholder", "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
        ("placeholder", "ghp" "_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"),
        ("placeholder", "AWS_SECRET_ACCESS_KEY=<redacted>"),
        ("placeholder", "password: ********"),
        ("placeholder", "token: ${{ secrets.GITHUB_TOKEN }}"),
        ("vocab", "To reset your password, click the link in the email we sent you."),
        ("vocab", "The access token expires after 60 minutes; request a new one with the refresh endpoint."),
        ("vocab", "Never commit your secret key to version control."),
        ("vocab", "def check_password(user, password):\n    return bcrypt.checkpw(password.encode(), user.pw_hash)"),
        ("vocab", "class TokenAuthMiddleware:\n    def __init__(self, get_response):\n        self.get_response = get_response"),
        ("vocab", "secret_santa_participants = ['ana', 'bo', 'cy']"),
        ("vocab", "api_key_validation_middleware_handler_function_registry = {}"),
        ("vocab", "access_key_rotation_policy_days = 90"),
        ("vocab", "token_bucket_rate_limiter_capacity = 100"),
        ("vocab", "password_policy_minimum_length_characters = 12"),
        ("vocab", "SELECT id, email FROM users WHERE password_hash IS NULL;"),
        ("vocab", "The JWT has three parts: header, payload and signature, separated by dots."),
        ("vocab", "ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519"),
        ("vocab", "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEexamplepublickeymaterialonlyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PUBLIC KEY-----"),
        ("vocab", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExamplePublicKeyOnlyNotSecret dev@laptop"),
        ("prose", "The build finished in 2m 14s and all 482 tests passed."),
        ("prose", "Traceback (most recent call last):\n  File \"app.py\", line 12, in <module>\n    main()\nKeyError: 'name'"),
        ("prose", "Created the file src/utils/helpers.py with three helper functions and updated the imports."),
        ("prose", "Here is the SQL migration:\nALTER TABLE orders ADD COLUMN shipped_at timestamp;"),
        ("prose", "The server listens on 0.0.0.0:8080 and logs to /var/log/app/app.log."),
        ("prose", "Summary: 3 files changed, 41 insertions(+), 7 deletions(-)"),
        ("prose", "Email me at dev@example.com if the deployment fails."),
        ("prose", "IP 203.0.113.42 was rate limited after 120 requests in 1 minute."),
        ("prose", "def fib(n):\n    a, b = 0, 1\n    for _ in range(n):\n        a, b = b, a + b\n    return a"),
        ("prose", "version = \"1.4.2\"\nrequires-python = \">=3.9\""),
        ("prose", "export PATH=\"$HOME/.local/bin:$PATH\""),
        ("prose", "https://github.com/acme/repo/commit/9fceb02d0ae598e95dc970b74767f19372d61af8"),
        ("prose", "Reading ~/.ssh/known_hosts to check the host fingerprint SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"),
    ]
    out.extend(fixed)
    return out


def build(seed=1234):
    rng = random.Random(seed)
    rows = []
    for name, maker in SECRET_MAKERS.items():
        for i in range(7):
            s = maker(rng)
            ctx = rng.choice(SECRET_CONTEXTS) if "\n" not in s else rng.choice(["{s}", "Key file contents:\n{s}\n", "cat key.pem\n{s}"])
            rows.append({"category": name, "text": ctx.format(s=s), "label": 1})
    for cat, t in negatives(rng):
        rows.append({"category": cat, "text": t, "label": 0})
    return rows


if __name__ == "__main__":
    r = build()
    print(len(r), sum(x["label"] for x in r))
