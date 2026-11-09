#!/usr/bin/env bash
# Runs inside a plain container (openssh-server and openssh-client installed,
# python3): writes authorized_keys lines that are hard for a parser to read,
# one line per file, and what "ssh-keygen -lf" and a real sshd make of each.
# capture.sh copies the directory out as testdata/ubuntuXXXX/keycases/. The
# keys are generated here, so the names below stand for fresh keys on each
# capture:
#   G    an ed25519 key (the expected one)
#   E    another ed25519 key (the attacker's)
#   R    an rsa key, C an ecdsa key
# Files: NN.keys is the input (exactly one line), NN.fp the "ssh-keygen -lf"
# stdout, NN.exit its exit status, NN.about a one-line description, NN.login
# which of the keys good, evil, rsa, ecdsa and goodcert (the good key as a
# certificate) a real sshd accepted for a login with that line as the only
# line of the user's authorized_keys file ("none" when it accepted none).
# KEYS holds the fingerprint of each key ("name SHA256:..."). The accounts for
# the login are made here; set KW_KC_LOGIN=0 to skip the logins.
set -eu
out=${1:-/tmp/kwkc}
rm -rf "$out"
mkdir -p "$out"
cd "$out"
mkdir -p k
for t in good evil; do ssh-keygen -q -t ed25519 -N "" -C "kw-$t" -f "k/$t"; done
ssh-keygen -q -t rsa -b 2048 -N "" -C kw-rsa -f k/rsa
ssh-keygen -q -t ecdsa -b 256 -N "" -C kw-ecdsa -f k/ecdsa
ssh-keygen -q -t ed25519 -N "" -C kw-ca -f k/ca
ssh-keygen -q -s k/ca -I kw-cert -n kwuser -V +52w k/good.pub
ssh-keygen -q -t dsa -N "" -C kw-dsa -f k/dsa
G=$(cut -d' ' -f2 k/good.pub)
E=$(cut -d' ' -f2 k/evil.pub)
R=$(cut -d' ' -f2 k/rsa.pub)
C=$(cut -d' ' -f2 k/ecdsa.pub)
CERT=$(cut -d' ' -f2 k/good-cert.pub)
D=$(cut -d' ' -f2 k/dsa.pub)
for k in good evil rsa ecdsa dsa; do
  printf '%s %s\n' "$k" "$(ssh-keygen -lf "k/$k.pub" | cut -d' ' -f2)"
done >KEYS
# blobs that no tool writes: built from the keys above
python3 - <<'PY'
import base64, struct
def s(x): return struct.pack('>I', len(x)) + x
def rd(path):
    return base64.b64decode(open(path).read().split()[1])
def fields(raw):
    out, off = [], 0
    while off < len(raw):
        n = struct.unpack('>I', raw[off:off + 4])[0]
        out.append(raw[off + 4:off + 4 + n]); off += 4 + n
    return out
def w(name, data):
    open('k/' + name, 'w').write(base64.b64encode(data).decode())
ev = rd('k/evil.pub'); rsa = fields(rd('k/rsa.pub')); ec = fields(rd('k/ecdsa.pub'))
pk = fields(ev)[1]
w('sk.b64', s(b'sk-ssh-ed25519@openssh.com') + s(pk) + s(b'ssh:'))
w('webauthn.b64', s(b'sk-ecdsa-sha2-nistp256@openssh.com') + s(b'nistp256') + s(ec[2]) + s(b'ssh:'))
w('trail.b64', ev + b'\0\0\0\0')
w('rsa_lz.b64', s(rsa[0]) + s(b'\x00' + rsa[1]) + s(rsa[2]))
w('rsa_lz3.b64', s(rsa[0]) + s(b'\x00\x00\x00' + rsa[1]) + s(b'\x00\x00' + rsa[2]))
# the modulus has its top bit set and a leading zero byte: without that byte it is negative
n = rsa[2]; assert n[0] == 0
w('rsa_neg.b64', s(rsa[0]) + s(rsa[1]) + s(n[1:]))
# the type string at the start of a blob: another name of the same type, or the short name
w('rsa_inner_short.b64', s(b'RSA') + s(rsa[1]) + s(rsa[2]))
w('rsa_inner_sha2.b64', s(b'rsa-sha2-256') + s(rsa[1]) + s(rsa[2]))
w('ed_inner_short.b64', s(b'Ed25519') + s(pk))
w('ec_inner_short.b64', s(b'ECDSA') + s(ec[1]) + s(ec[2]))
# an uncompressed point turned into a compressed one (0x02/0x03 and x only)
pt = ec[2]; assert pt[0] == 4
w('ec_comp.b64', s(ec[0]) + s(ec[1]) + s(bytes([2 + (pt[-1] & 1)]) + pt[1:33]))
PY
SK=$(cat k/sk.b64); WEB=$(cat k/webauthn.b64); TRAIL=$(cat k/trail.b64)
RIS=$(cat k/rsa_inner_short.b64); RI2=$(cat k/rsa_inner_sha2.b64); EIS=$(cat k/ed_inner_short.b64); CIS=$(cat k/ec_inner_short.b64)
RLZ=$(cat k/rsa_lz.b64); RLZ3=$(cat k/rsa_lz3.b64); RNEG=$(cat k/rsa_neg.b64); ECC=$(cat k/ec_comp.b64)
n=0
# A real sshd on 127.0.0.1:2222 for the account alice, with password login off.
# usermod -p '*' makes the account usable for key logins without a password.
login=${KW_KC_LOGIN:-1}
if [ "$login" = 1 ]; then
  id alice >/dev/null 2>&1 || useradd -m -u 1001 -s /bin/bash alice
  usermod -p '*' alice
  install -d -o alice -g alice -m 700 /home/alice/.ssh
  mkdir -p /run/sshd
  ssh-keygen -A >/dev/null 2>&1
  printf '%s\n' "Port 2222" "ListenAddress 127.0.0.1" "HostKey /etc/ssh/ssh_host_ed25519_key" \
    "PidFile $out/sshd.pid" "AuthorizedKeysFile .ssh/authorized_keys" "PasswordAuthentication no" \
    "KbdInteractiveAuthentication no" "PubkeyAuthentication yes" "UsePAM yes" "StrictModes yes" "LogLevel ERROR" >sshd_config
  /usr/sbin/sshd -f "$out/sshd_config"
  for i in 1 2 3 4 5 6 7 8 9 10; do
    (exec 3<>/dev/tcp/127.0.0.1/2222) 2>/dev/null && break
    sleep 0.5
  done
fi
# try <key> [ssh options]: whether sshd accepts the key for alice
try() {
  local key=$1
  shift
  timeout 20 ssh -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o LogLevel=ERROR -o ConnectTimeout=10 \
    -i "k/$key" "$@" -p 2222 alice@127.0.0.1 true >/dev/null 2>&1
}
# case <description> <printf format> [arguments]: the format is the whole file,
# a newline is added by the format when wanted
case_() {
  n=$((n + 1))
  local id
  id=$(printf '%02d' "$n")
  printf '%s\n' "$1" >"$id.about"
  shift
  # shellcheck disable=SC2059
  printf "$@" >"$id.keys"
  set +e
  ssh-keygen -lf "$id.keys" >"$id.fp" 2>/dev/null
  echo $? >"$id.exit"
  if [ "$login" = 1 ]; then
    cp "$id.keys" /home/alice/.ssh/authorized_keys
    chown alice:alice /home/alice/.ssh/authorized_keys
    chmod 600 /home/alice/.ssh/authorized_keys
    local acc=""
    try good -o CertificateFile=/dev/null -o PubkeyAcceptedAlgorithms=ssh-ed25519 && acc="$acc good"
    try evil -o PubkeyAcceptedAlgorithms=ssh-ed25519 && acc="$acc evil"
    try rsa && acc="$acc rsa"
    try ecdsa && acc="$acc ecdsa"
    try good -o CertificateFile=k/good-cert.pub -o PubkeyAcceptedAlgorithms=ssh-ed25519-cert-v01@openssh.com && acc="$acc goodcert"
    printf '%s\n' "${acc# }" | sed 's/^$/none/' >"$id.login"
  fi
  set -e
}
case_ "plain ed25519" 'ssh-ed25519 %s comment\n' "$G"
case_ "plain rsa" 'ssh-rsa %s comment\n' "$R"
case_ "plain ecdsa" 'ecdsa-sha2-nistp256 %s comment\n' "$C"
case_ "options" 'no-pty,command="id" ssh-ed25519 %s comment\n' "$G"
case_ "quoted blanks in the options" 'command="echo a  b" ssh-ed25519 %s comment\n' "$G"
case_ "escaped quotes inside the options" 'command="echo \\"a b\\"" ssh-ed25519 %s comment\n' "$G"
case_ "reviewer line: backslash before the closing quote hides the real key from a naive scan" 'command="id #\\\\" ssh-ed25519 %s x " ssh-ed25519 %s\n' "$G" "$E"
case_ "the same line with the attacker key first" 'command="id #\\\\" ssh-ed25519 %s x " ssh-ed25519 %s\n' "$E" "$G"
case_ "one backslash and a quote opens no quote outside quotes" 'foo\\"bar ssh-ed25519 %s comment\n' "$G"
case_ "backslash quote outside the options start" '\\"x ssh-ed25519 %s y" ssh-ed25519 %s\n' "$G" "$E"
case_ "three backslashes before the quote" 'command="a\\\\\\" ssh-ed25519 %s b" ssh-ed25519 %s\n' "$G" "$E"
case_ "four backslashes before the quote" 'command="a\\\\\\\\" ssh-ed25519 %s b" ssh-ed25519 %s\n' "$G" "$E"
case_ "backslash that does not precede a quote, inside quotes" 'command="a\\x b" ssh-ed25519 %s c\n' "$G"
case_ "unterminated quote" 'command="id ssh-ed25519 %s comment\n' "$G"
case_ "unterminated quote after an escaped quote" 'command="x\\" ssh-ed25519 %s\n' "$G"
case_ "options but no key type" 'command="id" %s comment\n' "$G"
case_ "options without a key at all" 'command="id"\n'
case_ "tabs between the fields" 'command="id"\tssh-ed25519\t%s\tcomment\n' "$G"
case_ "tab inside quotes" 'command="a\tb" ssh-ed25519 %s comment\n' "$G"
case_ "leading blanks" '  \t ssh-ed25519 %s comment\n' "$G"
case_ "several blanks between the fields" 'ssh-ed25519     %s     comment\n' "$G"
case_ "carriage return line ending" 'ssh-ed25519 %s comment\r\n' "$G"
case_ "the comment holds another key" 'ssh-ed25519 %s ssh-ed25519 %s\n' "$G" "$E"
case_ "a key type as the first option" 'ssh-rsa ssh-ed25519 %s\n' "$G"
case_ "options directly followed by the key type" 'command="x"ssh-ed25519 %s\n' "$G"
case_ "empty option string" '"" ssh-ed25519 %s comment\n' "$G"
case_ "unknown key type" 'ssh-foo %s comment\n' "$G"
case_ "certificate line" 'ssh-ed25519-cert-v01@openssh.com %s comment\n' "$CERT"
case_ "key type that does not match the blob" 'ssh-rsa %s comment\n' "$G"
case_ "no blob" 'ssh-ed25519\n'
case_ "no blob, trailing blank" 'ssh-ed25519 \n'
case_ "blob is not base64" 'ssh-ed25519 !!!notbase64 comment\n'
case_ "not base64 first, a valid key as the comment" 'ssh-ed25519 !!!notbase64 ssh-ed25519 %s\n' "$G"
case_ "second key type token is the blob position" 'ssh-ed25519 ssh-ed25519 %s\n' "$G"
case_ "host name before the key (known_hosts style)" 'example.test ssh-ed25519 %s\n' "$G"
case_ "NUL after the blob" 'ssh-ed25519 %s\0 comment\n' "$G"
case_ "NUL in the middle of the blob" 'ssh-ed25519 %s\0%s comment\n' "${G:0:20}" "${G:20}"
case_ "NUL inside the options" 'command="a\0b" ssh-ed25519 %s\n' "$G"
case_ "comment of 40000 bytes" 'ssh-ed25519 %s %s\n' "$G" "$(head -c 40000 /dev/zero | tr '\0' 'x')"
case_ "options of 20000 bytes" 'command="%s" ssh-ed25519 %s c\n' "$(head -c 20000 /dev/zero | tr '\0' 'x')" "$G"
case_ "long comment, then the attacker key" 'ssh-ed25519 %s %s ssh-ed25519 %s\n' "$G" "$(head -c 20000 /dev/zero | tr '\0' 'x')" "$E"
case_ "from option with a pattern" 'from="192.0.2.0/24,*.example.test",restrict ssh-ed25519 %s comment\n' "$G"
case_ "comment line then key" '# ssh-ed25519 %s\nssh-ed25519 %s\n' "$E" "$G"
case_ "key after a hash that is not at the line start" 'ssh-ed25519 %s # comment\n' "$G"
# an ecdsa blob is 104 bytes: its base64 text ends in one "=" and the character
# before it carries two bits that must be zero; set one of them
CPAD=$(perl -e '$s = shift; $a = join "", "A".."Z", "a".."z", 0..9, "+", "/"; $s =~ s/(.)=$/substr($a, index($a, $1) | 1, 1) . "="/e; print $s' "$C")
case_ "padding bits of the base64 text are not zero" 'ecdsa-sha2-nistp256 %s comment\n' "$CPAD"
case_ "base64 text with an inner blank" 'ssh-ed25519 %s %s\n' "${G:0:20}" "${G:20}"
case_ "blob with bytes appended" 'ssh-ed25519 %s comment\n' "$(printf '%s' "$G" | base64 -d | cat - <(printf 'junk') | base64 -w0)"
case_ "sk-ssh-ed25519 type with an ed25519 blob" 'sk-ssh-ed25519@openssh.com %s comment\n' "$G"
case_ "two spaces then key type uppercase" 'SSH-ED25519 %s comment\n' "$G"
# ---- key types and blobs that OpenSSH reads and a naive reader does not
case_ "rsa-sha2-256 as the key type of an ssh-rsa blob" 'rsa-sha2-256 %s x\n' "$R"
case_ "rsa-sha2-512 as the key type of an ssh-rsa blob" 'rsa-sha2-512 %s x\n' "$R"
case_ "RSA, the short name, is not a key type in this file" 'RSA %s x\n' "$R"
case_ "ECDSA, the short name" 'ECDSA %s x\n' "$C"
case_ "ED25519, the short name, with the attacker key" 'ED25519 %s x\n' "$E"
case_ "ed25519 in lower case, the short name" 'ed25519 %s x\n' "$E"
case_ "short name, then the real key as a second word" 'ED25519 %s ssh-ed25519 %s x\n' "$E" "$G"
case_ "ED25519-SK, the short name, with a security key blob" 'ED25519-SK %s x\n' "$SK"
case_ "sk-ssh-ed25519 with a security key blob" 'sk-ssh-ed25519@openssh.com %s x\n' "$SK"
case_ "webauthn-sk-ecdsa type with an sk-ecdsa blob" 'webauthn-sk-ecdsa-sha2-nistp256@openssh.com %s x\n' "$WEB"
case_ "ssh-dss" 'ssh-dss %s x\n' "$D"
case_ "rsa-sha2-256 type, but a ed25519 blob" 'rsa-sha2-256 %s x\n' "$E"
case_ "vertical tab inside the base64 text" 'ssh-ed25519 %s\v%s x\n' "${E:0:20}" "${E:20}"
case_ "form feed inside the base64 text" 'ssh-ed25519 %s\f%s x\n' "${E:0:20}" "${E:20}"
case_ "carriage return inside the base64 text" 'ssh-ed25519 %s\r%s x\n' "${E:0:20}" "${E:20}"
case_ "vertical tab between the key type and the base64 text" 'ssh-ed25519\v%s x\n' "$E"
case_ "base64 text with four trailing bytes after the key" 'ssh-ed25519 %s x\n' "$TRAIL"
case_ "rsa key with a zero byte in front of e and none of n" 'ssh-rsa %s x\n' "$RLZ"
case_ "rsa key with three zero bytes in front of e and two in front of n" 'ssh-rsa %s x\n' "$RLZ3"
case_ "rsa key with a negative modulus (top bit set, no zero byte in front)" 'ssh-rsa %s x\n' "$RNEG"
case_ "ecdsa key with a compressed point" 'ecdsa-sha2-nistp256 %s x\n' "$ECC"
case_ "vertical tab between the options and the key" 'command="a"\vssh-ed25519 %s x\n' "$G"
case_ "options, a short key type, the key" 'no-pty ED25519 %s x\n' "$E"
case_ "options, a short key type, then the real key" 'no-pty ED25519 %s ssh-ed25519 %s\n' "$E" "$G"
case_ "a carriage return in front of the key" '\rssh-ed25519 %s\n' "$E"
case_ "backslashes and a quote inside the quote" 'a="\\" ssh-ed25519 %s "\\" ssh-ed25519 %s\n' "$G" "$E"
case_ "unterminated quote, the real key after it" 'a="x ssh-ed25519 %s\n' "$G"
case_ "backslash before the closing quote of the options" 'command="x\\\\" ssh-ed25519 %s\n' "$E"
case_ "cert-authority option with a plain key" 'cert-authority ssh-ed25519 %s x\n' "$G"
case_ "cert-authority option with the certificate" 'cert-authority ssh-ed25519-cert-v01@openssh.com %s x\n' "$CERT"
case_ "ssh-rsa line, the blob calls its type RSA" 'ssh-rsa %s x\n' "$RIS"
case_ "ssh-rsa line, the blob calls its type rsa-sha2-256" 'ssh-rsa %s x\n' "$RI2"
case_ "ssh-ed25519 line, the blob calls its type Ed25519" 'ssh-ed25519 %s x\n' "$EIS"
case_ "ecdsa line, the blob calls its type ECDSA" 'ecdsa-sha2-nistp256 %s x\n' "$CIS"
if [ "$login" = 1 ]; then
  kill "$(cat "$out/sshd.pid")" 2>/dev/null || true
  rm -f /home/alice/.ssh/authorized_keys sshd_config sshd.pid
fi
rm -rf k
