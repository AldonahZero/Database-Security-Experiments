from flask import Flask, request, jsonify
import psycopg2
import psycopg2.extras
from pymongo import MongoClient
import time

app = Flask(__name__)

pg_conn = psycopg2.connect(
    host='postgres-db',
    dbname='juiceshop_db',
    user='youruser',
    password='password123'
)
pg_conn.autocommit = True

mongo_client = MongoClient('mongodb://mongo-db:27017')
mongo_db = mongo_client['vuln']


def fetch_rows_dict(cursor):
    columns = [desc[0] for desc in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


@app.route('/pg/users')
def pg_users():
    user_input = request.args.get('id', '1')
    query = f"SELECT id, username, secret FROM vuln_users WHERE id = {user_input};"
    start = time.time()
    cursor = pg_conn.cursor()
    cursor.execute(query)
    rows = fetch_rows_dict(cursor)
    duration_ms = (time.time() - start) * 1000
    return jsonify({
        'query': query,
        'rows': rows,
        'elapsed_ms': duration_ms
    })


@app.route('/mongo/login')
def mongo_login():
    query = {}
    for key, value in request.args.items():
        if '[' in key and key.endswith(']'):
            field, operator = key.split('[', 1)
            operator = operator[:-1]
            query.setdefault(field, {})['$' + operator] = value
        else:
            query[key] = value
    start = time.time()
    docs = list(mongo_db.accounts.find(query, {'_id': 0}))
    duration_ms = (time.time() - start) * 1000
    return jsonify({
        'query': query,
        'results': docs,
        'elapsed_ms': duration_ms
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8081)
