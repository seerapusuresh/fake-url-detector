from flask import Flask, render_template, request
from detector import analyze_url

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():
    result = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()

        if url:
            result = analyze_url(url)

    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)