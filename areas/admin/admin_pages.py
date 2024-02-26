from flask import Blueprint, request
from flask import flash, render_template, redirect, url_for
from flask_security import login_required
from .admin_services import create_newsletter, get_all_newsletter, get_newsletter, update_newsletter,get_newsletters_for_page
from .admin_services import send_newsletter as sender
from views.forms import EditNewsletter

admin_blueprint = Blueprint('admin', __name__)

@admin_blueprint.route('/admin', methods = ['GET', 'POST'])
@login_required
def admin() -> str:
    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('product.products',
                                    q = request.form['product_name_search']
                                    )
                                )
    return render_template('admin/admin.html')

@admin_blueprint.route('/admin/newsletters', methods=['GET', 'POST'])
def newsletters():
    page = request.args.get('page', 1, type=int)
    per_page = 10 

    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('product.products', q=request.form['product_name_search']))

    newsletters = get_newsletters_for_page(page, per_page)

    return render_template('admin/newsletters.html', newsletters=newsletters)

@admin_blueprint.route('/admin/newsletter/new', methods = ['GET', 'POST'])
@login_required
def new_newsletter() -> str:
    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('product.products',
                                    q = request.form['product_name_search']
                                    )
                                )
    newsletter_id = create_newsletter()
    return redirect(url_for('admin.edit_newsletter',
                            newsletter_id = newsletter_id
                            )
                        )

@admin_blueprint.route('/admin/newsletter/<newsletter_id>', methods = ['GET', 'POST'])
@login_required
def edit_newsletter(newsletter_id: int = None) -> str:
    newsletter = get_newsletter(newsletter_id)
    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('product.products',
                                    q = request.form['product_name_search']
                                    )
                                )
        update_newsletter(newsletter, request.form)

    form = EditNewsletter(subject = newsletter.subject,
                          content = newsletter.content)
    return render_template('admin/edit_newsletter.html',
                           newsletter = newsletter,
                           form = form)

@admin_blueprint.route('/admin/newsletters/send/<newsletter_id>', methods = ['GET', 'POST'])
@login_required
def send_newsletter(newsletter_id: int) -> str:
    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('product.products',
                                    q = request.form['product_name_search']
                                    )
                                )
    sender(newsletter_id)
    return redirect(url_for('admin.newsletters'))