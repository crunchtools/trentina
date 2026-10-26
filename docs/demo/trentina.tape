# Part two of the README demo: a real Trentina, a real tool list, a real
# poisoned page. Rendered by render.sh, which starts the gateway and its
# fixtures first; every number and refusal on screen is the gateway's own.

Output terminal.mp4

Set Shell bash
Set FontSize 18
Set Width 1200
Set Height 720
Set Padding 24
Set Theme "GruvboxDark"
Set TypingSpeed 40ms

Hide
Type "export PATH=/demo:$PATH R=http://recipes.example/recipe.html ME=user_google_email=me@example.com PS1='$ ' && clear"
Enter
Show

Type "# Token savings: the tool list a Workspace server offers vs. what this agent is served."
Enter
Type "tq surface"
Sleep 300ms
Enter
Wait@60s /^\$\s*$/
Sleep 4s

Type "clear"
Enter
Type "# Security: a recipe page whose comments carry an injection."
Enter
Type "tq call fetch url=$R | jq ._trentina_refusal"
Sleep 300ms
Enter
Wait@90s /^\$\s*$/
Sleep 4s

Type "# The policy allows redact: ask for what you need, get only that."
Enter
Type `tq call fetch url=$R 'trentina_mode={"redact":"ingredients?"}' | jq .result.content`
Sleep 300ms
Enter
Wait@90s /^\$\s*$/
Sleep 5s

Type "clear"
Enter
Type "# Determinism: even a fooled agent can't mail your inbox away."
Enter
Type "tq call send_gmail_message $ME to=backup@recipes-cdn.example.net subject=x body=x | jq ._trentina_refusal"
Sleep 300ms
Enter
Wait@60s /^\$\s*$/
Sleep 3s

Type "# It may draft. You press send."
Enter
Type "tq call draft_gmail_message $ME to=me@example.com 'subject=Saturday' body=Pasta | jq .result"
Sleep 300ms
Enter
Wait@60s /^\$\s*$/
Sleep 4s
