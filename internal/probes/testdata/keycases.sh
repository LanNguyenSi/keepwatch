#!/usr/bin/env bash
# Runs inside a plain container (openssh-client installed): writes authorized_keys
# lines that are hard for a parser to read, one line per file, and what
# "ssh-keygen -lf" makes of each. capture.sh copies the directory out as
# testdata/ubuntuXXXX/keycases/. The keys are generated here, so the names
# below stand for fresh keys on each capture:
#   G    an ed25519 key (the expected one)
#   E    another ed25519 key (the attacker's)
#   R    an rsa key, C an ecdsa key
# Files: NN.keys is the input (exactly one line), NN.fp the "ssh-keygen -lf"
# stdout, NN.exit its exit status, NN.about a one-line description.
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
G=$(cut -d' ' -f2 k/good.pub)
E=$(cut -d' ' -f2 k/evil.pub)
R=$(cut -d' ' -f2 k/rsa.pub)
C=$(cut -d' ' -f2 k/ecdsa.pub)
CERT=$(cut -d' ' -f2 k/good-cert.pub)
n=0
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
rm -rf k
