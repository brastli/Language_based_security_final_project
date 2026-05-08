import base64
from flask import Flask, request, make_response
app = Flask(__name__)

@app.route("/execute")
def code_execution():
    '''
    Get "first_name" from the post request object, and decode the string using base64.
    Then, call the setname function with the decoded first_name as argument.
    '''
    if request.method == 'POST':
        raw = request.args.get("first_name", "") or ""
        decoded = base64.b64decode(raw.encode("ascii"))
        first_name = decoded.decode("utf-8", errors="replace")
        exec("setname('%s')" % first_name)