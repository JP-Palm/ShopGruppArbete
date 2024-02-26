from flask import Blueprint, render_template, current_app, request, redirect, url_for, flash
from flask_security import roles_accepted
from models import User, db, Subscriber
import math
from .services import (get_products,
                       getCategory,
                       getCategoryname,
                       getTrendingCategories, 
                       getProduct, 
                       getTrendingProducts, 
                       getAllCategories, 
                       addCategory, 
                       addProduct, 
                       updateCategory, 
                       updateProduct, 
                       deleteCategory, 
                       deleteProduct)

productBluePrint = Blueprint('product', __name__)

@productBluePrint.route('/', methods = ['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('.products',
                                    q = request.form['product_name_search']
                                    )
                                )
    
    trendingCategories = getTrendingCategories()
    trendingProducts = getTrendingProducts()
    return render_template('products/index.html', trendingCategories=trendingCategories, products=trendingProducts)

@productBluePrint.route('/category/<id>', methods = ['GET', 'POST'])
def category(id):
    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('.products',
                                    q = request.form['product_name_search']
                                    )
                                )

    category = getCategory(id)
    return render_template('products/category.html', category=category)

@productBluePrint.route('/product/<id>', methods = ['GET', 'POST'])
def product(id):
    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('.products',
                                    q = request.form['product_name_search']
                                    )
                                )

    product = getProduct(id)
    return render_template('products/product.html', product=product)

@productBluePrint.route('/admin/catalog')
def admin_catalog():
    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('.products',
                                    q = request.form['product_name_search']
                                    )
                                )

    if not current_app.config.get('TEMP_ADMIN_ACCESS', False):
        return "Access Denied", 403
    
    sort_by = request.args.get('sort_by', 'ProductName')
    sort_order = request.args.get('sort_order', 'asc')    
    page = request.args.get('page', 1, type=int)          
    
    categories = getAllCategories()

    per_page = 10 
    
    # Sort products within each category!!!
    for category in categories:
        category.Products.sort(key=lambda x: getattr(x, sort_by), reverse=(sort_order == 'desc'))
    
    # Paginate products for each category
    for category in categories:
        total_products = len(category.Products)
        num_pages = math.ceil(total_products / per_page)
        category.page = page
        category.num_pages = num_pages
        start_index = (page - 1) * per_page
        end_index = start_index + per_page
        category.Products = category.Products[start_index:end_index]
        # Pass sorting parameters to each category
        category.sort_by = sort_by
        category.sort_order = sort_order
    
    return render_template('admin/catalog.html', categories=categories, sort_by=sort_by, sort_order=sort_order, page=page)


@productBluePrint.route('/add_product', methods=['GET', 'POST'])
def add_product():
    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('.products',
                                    q = request.form['product_name_search']
                                    )
                                )
        product_name = request.form.get('product_name')
        category_id = request.form.get('category_id')
        unit_price = request.form.get('unit_price')
        units_in_stock = request.form.get('units_in_stock')
        addProduct(product_name, category_id, unit_price, units_in_stock)
        flash('Product added successfully!')
        return redirect(url_for('.admin_catalog'))
    else:
        categories = getAllCategories()
        return render_template('admin/add_product.html', categories=categories)

@productBluePrint.route('/delete_product/<int:id>', methods = ['GET', 'POST'])
def delete_product(id):
    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('.products',
                                    q = request.form['product_name_search']
                                    )
                                )
    if deleteProduct(id):
        flash('Product deleted successfully!')
    else:
        flash('Error deleting product.')
    return redirect(url_for('.admin_catalog'))

@productBluePrint.route('/confirm_delete_product/<int:id>', methods = ['GET', 'POST'])
def confirm_delete_product(id):
    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('.products',
                                    q = request.form['product_name_search']
                                    )
                                )
    product = getProduct(id)
    return render_template('admin/confirm_delete_product.html', product=product)

@productBluePrint.route('/edit_product/<int:id>', methods=['GET', 'POST'])
def edit_product(id):
    product = getProduct(id)
    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('.products',
                                    q = request.form['product_name_search']
                                    )
                                )
        product_name = request.form['product_name']
        category_id = request.form['category_id']
        unit_price = request.form['unit_price']
        units_in_stock = request.form['units_in_stock']
        if updateProduct(id, product_name, category_id, unit_price, units_in_stock):
            flash('Product updated successfully!')
        else:
            flash('Error updating product.')
        return redirect(url_for('.admin_catalog'))
    categories = getAllCategories()
    return render_template('admin/edit_product.html', product=product, categories=categories)


@productBluePrint.route('/add_category', methods=['GET', 'POST'])
def add_category():
    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('.products',
                                    q = request.form['product_name_search']
                                    )
                                )
        category_name = request.form.get('category_name')
        description = request.form.get('description')
        existing_category = getCategoryname(category_name)
        if not existing_category:
            addCategory(category_name, description)
            flash('Category added successfully!')
            return redirect(url_for('.admin_catalog'))
        else:
            flash('Category with the same name already exists!', 'error')
            return redirect(url_for('.admin_catalog'))
    return render_template('admin/add_category.html')


@productBluePrint.route('/delete_category/<int:id>', methods=['GET', 'POST'])
def delete_category(id):
    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('.products',
                                    q = request.form['product_name_search']
                                    )
                                )
        if deleteCategory(id):
            flash('Category deleted successfully!')
            return redirect(url_for('.admin_catalog'))
        else:
            flash('Error deleting category.')
            return redirect(url_for('.admin_catalog'))
    else:
        category = getCategory(id)
        return render_template('admin/confirm_delete_category.html', category=category)


@productBluePrint.route('/confirm_delete_category/<int:id>', methods = ['GET', 'POST'])
def confirm_delete_category(id):
    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('.products',
                                    q = request.form['product_name_search']
                                    )
                                )
    category = getCategory(id)
    return render_template('admin/confirm_delete_category.html', category=category)


@productBluePrint.route('/edit_category/<int:id>', methods=['GET', 'POST'])
def edit_category(id):
    category = getCategory(id)
    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('.products',
                                    q = request.form['product_name_search']
                                    )
                                )
        category_name = request.form['category_name']
        description = request.form['description']
        if updateCategory(id, category_name, description):
            flash('Category updated successfully!')
        else:
            flash('Error updating category.')
        return redirect(url_for('.admin_catalog'))
    return render_template('admin/edit_category.html', category=category)

@productBluePrint.route('/products', methods = ['GET', 'POST'])
def products():
    if request.method == 'POST':
        if 'product_name_search' in request.form:
            return redirect(url_for('.products',
                                    q = request.form['product_name_search']
                                    )
                                )
    search_word = request.args.get('q', '')
    searched_products = get_products(search_word)
    return render_template('products/products.html',
                           products = searched_products,
                           q = search_word)