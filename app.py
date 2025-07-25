import os
import sqlite3
from datetime import datetime, timedelta
import random
import string
from faker import Faker
import pandas as pd
import numpy as np
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO

app = Flask(__name__)
app.secret_key = 'your_very_secret_key_here'
fake = Faker()

# Database setup
def init_db():
    conn = sqlite3.connect('data_product_platform.db')
    c = conn.cursor()
    
    # Drop tables if they exist to ensure clean initialization
    c.execute("DROP TABLE IF EXISTS users")
    c.execute("DROP TABLE IF EXISTS data_products")
    c.execute("DROP TABLE IF EXISTS access_requests")
    c.execute("DROP TABLE IF EXISTS api_calls")
    c.execute("DROP TABLE IF EXISTS feedback")
    
    # Create tables with all required columns
    c.execute('''CREATE TABLE users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE,
                 password TEXT,
                 email TEXT,
                 role TEXT,
                 api_key TEXT,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    c.execute('''CREATE TABLE data_products
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT,
                 description TEXT,
                 category TEXT,
                 access_level TEXT,
                 api_endpoint TEXT,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    c.execute('''CREATE TABLE access_requests
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER,
                 product_id INTEGER,
                 status TEXT DEFAULT 'pending',
                 requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 reviewed_at TIMESTAMP,
                 reviewed_by INTEGER,
                 FOREIGN KEY(user_id) REFERENCES users(id),
                 FOREIGN KEY(product_id) REFERENCES data_products(id),
                 FOREIGN KEY(reviewed_by) REFERENCES users(id))''')
    
    c.execute('''CREATE TABLE api_calls
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER,
                 product_id INTEGER,
                 endpoint TEXT,
                 called_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 FOREIGN KEY(user_id) REFERENCES users(id),
                 FOREIGN KEY(product_id) REFERENCES data_products(id))''')
    
    c.execute('''CREATE TABLE feedback
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER,
                 product_id INTEGER,
                 rating INTEGER,
                 comments TEXT,
                 data_quality INTEGER,
                 data_completeness INTEGER,
                 ease_of_use INTEGER,
                 feedback_type TEXT,
                 message TEXT,
                 submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 FOREIGN KEY(user_id) REFERENCES users(id),
                 FOREIGN KEY(product_id) REFERENCES data_products(id))''')
    
    # Create admin user
    hashed_password = generate_password_hash('admin123')
    c.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
              ('admin', hashed_password, 'admin@dataproducts.com', 'admin'))
    
    # Create sample users
    for i in range(5):
        username = f'user{i+1}'
        hashed_password = generate_password_hash(f'password{i+1}')
        c.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                  (username, hashed_password, f'{username}@example.com', 'user'))
    
    # Create sample data products
    products = [
        ('Consumer Behavior Dataset', 'Detailed consumer purchase patterns across regions', 'Marketing', 'restricted', '/api/v1/consumer-behavior'),
        ('Financial Market Trends', 'Daily stock market indicators and trends', 'Finance', 'restricted', '/api/v1/financial-trends'),
        ('Weather History API', 'Historical weather data for global locations', 'Environment', 'open', '/api/v1/weather'),
        ('Healthcare Statistics', 'Public health indicators and disease prevalence', 'Healthcare', 'restricted', '/api/v1/health-stats'),
        ('E-commerce Metrics', 'Aggregated metrics from top e-commerce platforms', 'Retail', 'restricted', '/api/v1/ecommerce'),
        ('Social Media Sentiment', 'Aggregated sentiment analysis from social platforms', 'Marketing', 'restricted', '/api/v1/sentiment'),
        ('Real Estate Prices', 'Historical and current real estate pricing data', 'Real Estate', 'restricted', '/api/v1/real-estate'),
    ]
    
    for product in products:
        c.execute("INSERT INTO data_products (name, description, category, access_level, api_endpoint) VALUES (?, ?, ?, ?, ?)", product)
    
    # Create sample feedback
    #feedback_types = ['bug', 'feature_request', 'general_feedback', 'help_request']
    #for i in range(1, 6):
    #    user_id = i
    #    product_id = random.randint(1, 7)
    #    c.execute('''INSERT INTO feedback 
    #                (user_id, product_id, feedback_type, message, submitted_at)
    #                VALUES (?, ?, ?, ?, datetime('now', ?))''',
    #             (user_id, product_id, random.choice(feedback_types), 
    #              f'Sample feedback message {i}', f'-{i} days'))
    
    conn.commit()
    conn.close()

def generate_api_key():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

def generate_synthetic_data(product_id, rows=10):
    if product_id == 1:  # Consumer Behavior
        data = {
            'customer_id': [fake.uuid4() for _ in range(rows)],
            'age': [random.randint(18, 70) for _ in range(rows)],
            'income_bracket': [random.choice(['low', 'medium', 'high']) for _ in range(rows)],
            'purchase_category': [random.choice(['electronics', 'clothing', 'groceries', 'home']) for _ in range(rows)],
            'purchase_amount': [round(random.uniform(10, 500), 2) for _ in range(rows)],
            'region': [fake.state() for _ in range(rows)],
            'date': [fake.date_between(start_date='-1y') for _ in range(rows)]
        }
    elif product_id == 2:  # Financial Market Trends
        data = {
            'date': [fake.date_between(start_date='-1y') for _ in range(rows)],
            'symbol': [random.choice(['AAPL', 'MSFT', 'GOOG', 'AMZN', 'TSLA']) for _ in range(rows)],
            'open_price': [round(random.uniform(100, 500), 2) for _ in range(rows)],
            'close_price': [round(random.uniform(100, 500), 2) for _ in range(rows)],
            'volume': [random.randint(100000, 5000000) for _ in range(rows)],
            'market_cap': [random.randint(1000000000, 2000000000) for _ in range(rows)]
        }
    elif product_id == 3:  # Weather History
        data = {
            'date': [fake.date_between(start_date='-1y') for _ in range(rows)],
            'location': [fake.city() for _ in range(rows)],
            'temperature_high': [random.randint(60, 100) for _ in range(rows)],
            'temperature_low': [random.randint(30, 70) for _ in range(rows)],
            'precipitation': [round(random.uniform(0, 2), 2) for _ in range(rows)],
            'conditions': [random.choice(['sunny', 'cloudy', 'rainy', 'snowy']) for _ in range(rows)]
        }
    else:  # Default for other products
        data = {
            'id': [fake.uuid4() for _ in range(rows)],
            'value': [round(random.uniform(0, 1000), 2) for _ in range(rows)],
            'category': [random.choice(['A', 'B', 'C', 'D']) for _ in range(rows)],
            'timestamp': [fake.date_time_this_year() for _ in range(rows)]
        }
    
    return pd.DataFrame(data).to_dict(orient='records')

def generate_platform_metrics():
    conn = sqlite3.connect('data_product_platform.db')
    c = conn.cursor()
    
    # Total users
    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0]
    
    # Active users (last 7 days)
    week_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
    c.execute("SELECT COUNT(DISTINCT user_id) FROM api_calls WHERE called_at > ?", (week_ago,))
    active_users = c.fetchone()[0]
    
    # Total API calls
    c.execute("SELECT COUNT(*) FROM api_calls")
    total_api_calls = c.fetchone()[0]
    
    # API calls last 7 days
    c.execute("SELECT COUNT(*) FROM api_calls WHERE called_at > ?", (week_ago,))
    recent_api_calls = c.fetchone()[0]
    
    # Access requests
    c.execute("SELECT COUNT(*) FROM access_requests")
    total_requests = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM access_requests WHERE status='pending'")
    pending_requests = c.fetchone()[0]
    
    # Feedback stats
    c.execute("SELECT COUNT(*) FROM feedback")
    total_feedback = c.fetchone()[0]
    
    c.execute("SELECT AVG(rating) FROM feedback WHERE rating IS NOT NULL")
    avg_rating = c.fetchone()[0] or 0
    
    # Simulate NPS (Net Promoter Score)
    c.execute("SELECT COUNT(*) FROM feedback WHERE rating >= 9")
    promoters = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM feedback WHERE rating BETWEEN 7 AND 8")
    passives = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM feedback WHERE rating <= 6")
    detractors = c.fetchone()[0] or 0
    total_responses = promoters + passives + detractors
    nps = ((promoters - detractors) / total_responses) * 100 if total_responses > 0 else 0
    
    conn.close()
    
    return {
        'total_users': total_users,
        'active_users': active_users,
        'total_api_calls': total_api_calls,
        'recent_api_calls': recent_api_calls,
        'total_requests': total_requests,
        'pending_requests': pending_requests,
        'avg_rating': round(avg_rating, 1),
        'nps': round(nps, 1),
        'total_feedback': total_feedback,
        'uptime': '99.98%',
        'data_products': 7
    }

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('data_product_platform.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[4]
            
            if not user[5]:
                conn = sqlite3.connect('data_product_platform.db')
                c = conn.cursor()
                api_key = generate_api_key()
                c.execute("UPDATE users SET api_key=? WHERE id=?", (api_key, user[0]))
                conn.commit()
                conn.close()
                session['api_key'] = api_key
            else:
                session['api_key'] = user[5]
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('landing'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('data_product_platform.db')
    c = conn.cursor()
    
    if session['role'] == 'admin':
        # Get pending access requests
        c.execute('''SELECT ar.id, u.username, dp.name, ar.status, ar.requested_at 
                     FROM access_requests ar
                     JOIN users u ON ar.user_id = u.id
                     JOIN data_products dp ON ar.product_id = dp.id
                     WHERE ar.status = 'pending'
                     ORDER BY ar.requested_at DESC''')
        requests = c.fetchall()
        
        # Get popular products
        c.execute('''SELECT dp.name, COUNT(ar.id) as request_count
                     FROM data_products dp
                     LEFT JOIN access_requests ar ON dp.id = ar.product_id
                     GROUP BY dp.name
                     ORDER BY request_count DESC LIMIT 5''')
        popular_products = c.fetchall()
        
        # Get recent activity
        c.execute('''SELECT u.username, dp.name, ac.called_at 
                     FROM api_calls ac
                     JOIN users u ON ac.user_id = u.id
                     JOIN data_products dp ON ac.product_id = dp.id
                     ORDER BY ac.called_at DESC LIMIT 10''')
        recent_activity = c.fetchall()
        
        # Get recent ratings
        c.execute('''SELECT u.username, dp.name, f.rating, 
                     COALESCE(f.comments, '') as comments, f.submitted_at
                     FROM feedback f
                     JOIN users u ON f.user_id = u.id
                     LEFT JOIN data_products dp ON f.product_id = dp.id
                     WHERE f.rating IS NOT NULL
                     ORDER BY f.submitted_at DESC LIMIT 5''')
        recent_ratings = c.fetchall()
        
        # Get recent feedback messages
        c.execute('''SELECT u.username, COALESCE(dp.name, 'General') as product_name, 
                     f.feedback_type, f.message, f.submitted_at
                     FROM feedback f
                     JOIN users u ON f.user_id = u.id
                     LEFT JOIN data_products dp ON f.product_id = dp.id
                     WHERE f.message IS NOT NULL
                     ORDER BY f.submitted_at DESC LIMIT 5''')
        recent_feedback = c.fetchall()
        
        metrics = generate_platform_metrics()
        
        conn.close()
        return render_template('admin_dashboard.html', 
                             requests=requests,
                             popular_products=popular_products,
                             recent_activity=recent_activity,
                             recent_ratings=recent_ratings,
                             recent_feedback=recent_feedback,
                             metrics=metrics)
    else:
        c.execute('''SELECT dp.id, dp.name, dp.description, dp.category,
                     COALESCE(
                         (SELECT status FROM access_requests 
                          WHERE user_id = ? AND product_id = dp.id
                          ORDER BY requested_at DESC LIMIT 1),
                         'not_requested'
                     ) as access_status
                     FROM data_products dp''',
                  (session['user_id'],))
        products = c.fetchall()
        
        c.execute('''SELECT dp.name, ac.called_at 
                     FROM api_calls ac
                     JOIN data_products dp ON ac.product_id = dp.id
                     WHERE ac.user_id = ?
                     ORDER BY ac.called_at DESC LIMIT 5''', (session['user_id'],))
        recent_activity = c.fetchall()
        
        conn.close()
        return render_template('user_dashboard.html', 
                             products=products, 
                             recent_activity=recent_activity,
                             api_key=session.get('api_key', ''))

@app.route('/request_access', methods=['POST'])
@app.route('/request_access/<int:product_id>', methods=['POST'])
def request_access(product_id=None):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('data_product_platform.db')
    c = conn.cursor()
    
    if product_id:
        product_ids = [product_id]
    else:
        product_ids = request.form.getlist('product_ids')
    
    if not product_ids:
        flash('No products selected', 'warning')
        conn.close()
        return redirect(url_for('dashboard'))
    
    success_count = 0
    for pid in product_ids:
        try:
            c.execute("SELECT id FROM access_requests WHERE user_id=? AND product_id=? AND status IN ('pending', 'approved')",
                      (session['user_id'], pid))
            if c.fetchone():
                continue
            
            c.execute("INSERT INTO access_requests (user_id, product_id) VALUES (?, ?)",
                      (session['user_id'], pid))
            success_count += 1
        except Exception as e:
            print(f"Error processing product {pid}: {str(e)}")
            continue
    
    if success_count > 0:
        conn.commit()
        flash(f'Successfully submitted {success_count} access request(s)!', 'success')
    else:
        flash('All selected products already have pending or approved requests', 'warning')
    
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/manage_request/<int:request_id>/<action>')
def manage_request(request_id, action):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    if action not in ['approve', 'reject']:
        flash('Invalid action', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = sqlite3.connect('data_product_platform.db')
    c = conn.cursor()
    
    c.execute("UPDATE access_requests SET status=?, reviewed_at=CURRENT_TIMESTAMP, reviewed_by=? WHERE id=?",
              ('approved' if action == 'approve' else 'rejected', session['user_id'], request_id))
    conn.commit()
    conn.close()
    
    flash(f'Request {action}d successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/api/docs')
def api_docs():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('api_docs.html', api_key=session.get('api_key', ''))

@app.route('/api/v1/<path:endpoint>')
def api_endpoint(endpoint):
    api_key = request.args.get('api_key') or request.headers.get('Authorization', '').replace('Bearer ', '')
    
    conn = sqlite3.connect('data_product_platform.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE api_key=?", (api_key,))
    user = c.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'error': 'Invalid API key'}), 401
    
    user_id = user[0]
    
    c.execute("SELECT id, name, access_level FROM data_products WHERE api_endpoint=?", (f'/api/v1/{endpoint}',))
    product = c.fetchone()
    
    if not product:
        conn.close()
        return jsonify({'error': 'Endpoint not found'}), 404
    
    product_id, product_name, access_level = product
    
    if access_level == 'restricted':
        c.execute("SELECT id FROM access_requests WHERE user_id=? AND product_id=? AND status='approved'",
                  (user_id, product_id))
        if not c.fetchone():
            conn.close()
            return jsonify({'error': 'Access not granted for this endpoint'}), 403
    
    c.execute("INSERT INTO api_calls (user_id, product_id, endpoint) VALUES (?, ?, ?)",
              (user_id, product_id, endpoint))
    conn.commit()
    conn.close()
    
    data = generate_synthetic_data(product_id, rows=random.randint(5, 20))
    return jsonify({
        'product': product_name,
        'endpoint': endpoint,
        'data': data,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/download_dataset/<int:product_id>')
def download_dataset(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('data_product_platform.db')
    c = conn.cursor()
    
    # Check if user has access to this product
    c.execute('''SELECT 1 FROM access_requests 
                 WHERE user_id=? AND product_id=? AND status='approved' LIMIT 1''',
              (session['user_id'], product_id))
    if not c.fetchone():
        flash('Access not granted for this dataset', 'danger')
        conn.close()
        return redirect(url_for('dashboard'))
    
    # Get product details
    c.execute("SELECT name FROM data_products WHERE id=?", (product_id,))
    product_name = c.fetchone()[0]
    conn.close()
    
    # Generate the dataset
    data = generate_synthetic_data(product_id, rows=1000)  # Larger dataset for download
    df = pd.DataFrame(data)
    
    # Create CSV in memory
    output = BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)
    
    # Log the download
    conn = sqlite3.connect('data_product_platform.db')
    c = conn.cursor()
    c.execute("INSERT INTO api_calls (user_id, product_id, endpoint) VALUES (?, ?, ?)",
              (session['user_id'], product_id, f'download_{product_name}'))
    conn.commit()
    conn.close()
    
    filename = f"{product_name.lower().replace(' ', '_')}_dataset.csv"
    return send_file(output, mimetype='text/csv', as_attachment=True, download_name=filename)

@app.route('/submit_rating', methods=['POST'])
def submit_rating():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    product_id = request.form.get('product_id')
    data_quality = request.form.get('data_quality')
    data_completeness = request.form.get('data_completeness')
    ease_of_use = request.form.get('ease_of_use')
    overall_rating = request.form.get('overall_rating')
    comments = request.form.get('comments', '')
    
    if not all([product_id, data_quality, data_completeness, ease_of_use, overall_rating]):
        flash('Please complete all rating fields', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = sqlite3.connect('data_product_platform.db')
    c = conn.cursor()
    
    # Check if user has access to this product
    c.execute('''SELECT 1 FROM access_requests 
                 WHERE user_id=? AND product_id=? AND status='approved' LIMIT 1''',
              (session['user_id'], product_id))
    if not c.fetchone():
        flash('You need access to this product to submit ratings', 'danger')
        conn.close()
        return redirect(url_for('dashboard'))
    
    # Store the rating
    c.execute('''INSERT INTO feedback 
                 (user_id, product_id, rating, comments, data_quality, data_completeness, ease_of_use)
                 VALUES (?, ?, ?, ?, ?, ?, ?)''',
              (session['user_id'], product_id, overall_rating, comments, 
               data_quality, data_completeness, ease_of_use))
    conn.commit()
    conn.close()
    
    flash('Thank you for your rating!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    product_id = request.form.get('product_id', '')
    feedback_type = request.form.get('feedback_type')
    message = request.form.get('message')
    
    if not feedback_type or not message:
        flash('Please provide feedback type and message', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = sqlite3.connect('data_product_platform.db')
    c = conn.cursor()
    
    # If product-specific feedback, verify access
    if product_id and product_id != 'None':
        c.execute('''SELECT 1 FROM access_requests 
                     WHERE user_id=? AND product_id=? AND status='approved' LIMIT 1''',
                  (session['user_id'], product_id))
        if not c.fetchone():
            flash('You need access to this product to submit feedback', 'danger')
            conn.close()
            return redirect(url_for('dashboard'))
    
    # Store the feedback
    c.execute('''INSERT INTO feedback 
                 (user_id, product_id, feedback_type, message)
                 VALUES (?, ?, ?, ?)''',
              (session['user_id'], product_id if product_id and product_id != 'None' else None, feedback_type, message))
    conn.commit()
    conn.close()
    
    flash('Thank you for your feedback!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/case_studies')
def case_studies():
    case_studies = [
        {
            'title': 'Retail Chain Boosts Sales by 15%',
            'company': 'National Retail Co.',
            'industry': 'Retail',
            'challenge': 'Identifying optimal product placements and promotions',
            'solution': 'Used Consumer Behavior Dataset to analyze purchase patterns',
            'results': '15% increase in sales, 20% improvement in promotion targeting'
        },
        {
            'title': 'Financial Firm Reduces Risk Exposure',
            'company': 'Global Investments LLC',
            'industry': 'Finance',
            'challenge': 'Need for real-time market trend analysis',
            'solution': 'Integrated Financial Market Trends API into risk models',
            'results': '30% faster risk detection, 25% reduction in exposure'
        },
        {
            'title': 'Weather App Sees 2M New Users',
            'company': 'WeatherPro Mobile',
            'industry': 'Technology',
            'challenge': 'Lack of historical data for premium features',
            'solution': 'Leveraged Weather History API for new premium tier',
            'results': '2M new paid users in 6 months, 40% revenue increase'
        }
    ]
    return render_template('case_studies.html', case_studies=case_studies)

if __name__ == '__main__':
    # Force database reinitialization to ensure all tables and columns exist
    init_db()
    app.run(debug=True)