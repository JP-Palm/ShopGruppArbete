from sqlalchemy import select

from models import db, Category, Product

def getTrendingCategories():
    return Category.query.order_by(Category.CategoryID.desc()).paginate(page=1,per_page=4,error_out=False).items

def getCategory(id):
    return Category.query.filter(Category.CategoryID ==id).first()

def getCategoryname(name):
    return Category.query.filter_by(CategoryName=name).first()

def getProduct(id):
    return Product.query.filter(Product.ProductID ==id).first()

def getTrendingProducts():
    return Product.query.order_by(Product.ProductID.desc()).paginate(page=1,per_page=8,error_out=False).items

def getAllCategories():
    return Category.query.all()

# def getAllSuppliers():
#     return Supplier.query.all()

def addCategory(name, description):
    new_category = Category(CategoryName=name, Description=description)
    db.session.add(new_category)
    db.session.commit()

def addProduct(name, category_id, unit_price, units_in_stock):
    new_product = Product(
        ProductName=name,
        CategoryId=category_id,
        UnitPrice=unit_price,
        UnitsInStock=units_in_stock
        # Set other fields as needed
    )
    db.session.add(new_product)
    db.session.commit()

def updateCategory(id, name, description):
    category = Category.query.get(id)
    if category:
        category.CategoryName = name
        category.Description = description
        db.session.commit()
        
def updateProduct(id, name, category_id, unit_price, units_in_stock):
    product = Product.query.get(id)
    if product:
        product.ProductName = name
        product.CategoryId = category_id
        product.UnitPrice = unit_price
        product.UnitsInStock = units_in_stock
        db.session.commit()
        
def deleteCategory(id):
    category = Category.query.get(id)
    if category:
        db.session.delete(category)
        db.session.commit()
        
def deleteProduct(id):
    product = Product.query.get(id)
    if product:
        db.session.delete(product)
        db.session.commit()


def toggle_sort(attribute, current_order):
    # Toggles sorting order between ascending and descending
    return 'desc' if current_order == 'asc' else 'asc'
def get_products(search_word: str) -> list[Product]:
    stmt = select(Product).where(Product.ProductName.like(f'%{search_word}%'))
    return db.session.execute(stmt).scalars().all()
