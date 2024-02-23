from flask import Blueprint, request
from flask import flash, render_template, redirect, url_for

from .admin_services import create_newsletter, get_all_newsletter, get_newsletter, update_newsletter
from .admin_services import send_newsletter as sender
from views.forms import EditNewsletter

admin_blueprint = Blueprint('admin', __name__)

@admin_blueprint.route('/admin', methods = ['GET', 'POST'])
def admin() -> str:
    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('product.products',
                                    q = request.form['product_name_search']
                                    )
                                )
    return render_template('admin/admin.html')

@admin_blueprint.route('/admin/newsletters', methods = ['GET', 'POST'])
def newsletters() -> str:
    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('product.products',
                                    q = request.form['product_name_search']
                                    )
                                )

    all_newsletters = get_all_newsletter()
    return render_template('admin/newsletters.html',
                           newsletters = all_newsletters
                           )

@admin_blueprint.route('/admin/newsletter/new', methods = ['GET', 'POST'])
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
def send_newsletter(newsletter_id: int) -> str:
    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('product.products',
                                    q = request.form['product_name_search']
                                    )
                                )
    sender(newsletter_id)
    return redirect(url_for('admin.newsletters'))