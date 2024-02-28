from flask import Blueprint, render_template, request, redirect, url_for, flash
from models import User, db,Subscriber


siteBluePrint = Blueprint('site', __name__)


@siteBluePrint.route('/contact', methods = ['GET', 'POST'])
def contact() -> str:
     if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('product.products',
                                    q = request.form['product_name_search']
                                    )
                                )
     return render_template('site/contact.html')


@siteBluePrint.route('/terms', methods = ['GET', 'POST'])
def terms() -> str:
     if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('product.products',
                                    q = request.form['product_name_search']
                                    )
                                )
     return render_template('site/terms.html')


@siteBluePrint.route('/about', methods = ['GET', 'POST'])
def about() -> str:
     if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('product.products',
                                    q = request.form['product_name_search']
                                    )
                                )
     return render_template('site/about.html')


@siteBluePrint.route('/subscribe', methods = ['GET', 'POST'])
def subscribe():
    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('product.products',
                                    q = request.form['product_name_search']
                                    )
                                )
    email = request.form.get('email')
    #print(email)
    existing_subscriber = Subscriber.query.filter_by(email=email).first()
    if existing_subscriber:
        flash('Email already used. Please choose another one.', 'error')
    else:
        new_subscriber = Subscriber(email=email, active=True)
        db.session.add(new_subscriber)
        db.session.commit()
        flash('Subscription successful', 'success')

        return 'Welcome to the Group3 family! 🎉 Get ready for a delightful dose of inspiration, insights, and exclusive content delivered straight to your inbox.'