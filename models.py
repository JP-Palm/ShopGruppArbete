import barnum
from datetime import datetime
from flask import Flask
from flask_security import (hash_password,
                            RoleMixin,
                            Security,
                            SQLAlchemyUserDatastore,
                            UserMixin
                            )
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, select
from sqlalchemy.orm import (DeclarativeBase,
                            Mapped,
                            mapped_column,
                            relationship
                            )
from typing import List


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)


class Category(db.Model):
    __tablename__= "Categories"
    CategoryID: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    CategoryName: Mapped[str] = mapped_column(db.String(80), unique=False, nullable=False)
    Description: Mapped[str] = mapped_column(db.String(80), unique=False, nullable=False)
    Image: Mapped[str] = mapped_column(db.String(100), unique=True, nullable=True)

    Products: Mapped[List['Product']] = relationship('Product', backref='Category',lazy=True)


class Product(db.Model):
    __tablename__= "Products"
    ProductID: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    ProductName: Mapped[str] = mapped_column(db.String(40), unique=False, nullable=False)
    SupplierID: Mapped[int] = mapped_column(db.Integer, unique=False, nullable=False)
    CategoryId: Mapped[int] = mapped_column(db.Integer, db.ForeignKey('Categories.CategoryID'), nullable=False)
    QuantityPerUnit: Mapped[str] = mapped_column(db.String(20), unique=False, nullable=False)
    UnitPrice: Mapped[float] = mapped_column(db.Float, unique=False, nullable=False)
    UnitsInStock: Mapped[int] = mapped_column(db.Integer, unique=False, nullable=False)
    UnitsOnOrder: Mapped[int] = mapped_column(db.Integer, unique=False, nullable=False)
    ReorderLevel: Mapped[int] = mapped_column(db.Integer, unique=False, nullable=False)
    Discontinued: Mapped[int] = mapped_column(db.Boolean, unique=False, nullable=False)


class Role(db.Model, RoleMixin):
    __tablename__ = "roles"
    id: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    name: Mapped[str] = mapped_column(db.String(50), unique=True, nullable=True)


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    active: Mapped[bool] = mapped_column(db.Boolean())
    email: Mapped[str] = mapped_column(db.String(255), unique=True)
    email_confirmed_at: Mapped[datetime] = mapped_column(db.DateTime, nullable=True)
    password: Mapped[str] = mapped_column(db.String(255))
    first_name: Mapped[str] = mapped_column(db.String(100))
    last_name: Mapped[str] = mapped_column(db.String(100))
    fs_uniquifier: Mapped[str] = mapped_column(db.String(255), unique=True)

    roles: Mapped[List['Role']] = relationship('Role', secondary='user_roles', backref='User')


class UserRole(db.Model):
    __tablename__ = 'user_roles'
    id: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(db.Integer, db.ForeignKey(User.id))
    RoleID: Mapped[int] = mapped_column(db.Integer, db.ForeignKey(Role.id))


class Newsletter(db.Model):
    __tablename__ = 'Newsletters'
    id: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    subject: Mapped[str] = mapped_column(db.String(100))            # Mirrors email subject line
    content: Mapped[str] = mapped_column(db.String(2000))           # Mirrors email text content
    last_edit: Mapped[datetime] = mapped_column(db.DateTime)
    is_sent: Mapped[bool] = mapped_column(db.Boolean())
    date_sent: Mapped[datetime] = mapped_column(db.DateTime, nullable=True)


class Subscriber(db.Model):
    __tablename__ = 'Subscribers'
    id: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    email: Mapped[str] = mapped_column(db.String(255), unique=True)
    active: Mapped[bool] = mapped_column(db.Boolean())


user_datastore = SQLAlchemyUserDatastore(db, User, Role)

def seedData(app: Flask):
    app.security = Security(app, user_datastore)
    app.security.datastore.db.create_all()
    if not app.security.datastore.find_role("Admin"):
        app.security.datastore.create_role(name="Admin")
    if not app.security.datastore.find_role("Staff"):
        app.security.datastore.create_role(name="Staff")
    if not app.security.datastore.find_user(email="admin@systementor.se"):
        first_name, last_name = barnum.create_name()
        app.security.datastore.create_user(email="admin@systementor.se", password=hash_password("password"),roles=["Admin"], first_name = first_name, last_name = last_name, email_confirmed_at = datetime.now())
    if not app.security.datastore.find_user(email="worker1@systementor.se"):
        first_name, last_name = barnum.create_name()
        app.security.datastore.create_user(email="worker1@systementor.se", password=hash_password("password"),roles=["Staff"], first_name = first_name, last_name = last_name, email_confirmed_at = datetime.now())
    if not app.security.datastore.find_user(email="worker2@systementor.se"):
        first_name, last_name = barnum.create_name()
        app.security.datastore.create_user(email="worker2@systementor.se", password=hash_password("password"),roles=["Staff"], first_name = first_name, last_name = last_name, email_confirmed_at = datetime.now())
    app.security.datastore.db.session.commit()

    addCat(db,  "Beverages",	"Soft drinks, coffees, teas, beers, and ales")        
    addCat(db,  "Condiments",	"Sweet and savory sauces, relishes, spreads, and seasonings")        
    addCat(db,  "Confections",	"Desserts, candies, and sweet breads")        
    addCat(db, "Dairy Products","Cheeses")        
    addCat(db, "Grains/Cereals","Breads, crackers, pasta, and cereal")        
    addCat(db, "Meat/Poultry","Prepared meats")        
    addCat(db, "Produce","Dried fruit and bean curd")        
    addCat(db, "Seafood","Seaweed and fish")        
    addProduct(db,"Chai",	1,1	,"10 boxes x 20 bags",	18.0000	,	39	,	0	,	10	,	0	)
    addProduct(db,"Chang",	1,1	,"24 - 12 oz bottles",	19.0000	,	17	,	40	,	25	,	0	)
    addProduct(db,"Aniseed Syrup",	1,2	,"12 - 550 ml bottles",	10.0000	,	13	,	70	,	25	,	0	)
    addProduct(db,"Chef Anton's Cajun Seasoning",	2,2	,"48 - 6 oz jars",	22.0000	,	53	,	0	,	0	,	0	)
    addProduct(db,"Chef Anton's Gumbo Mix",	2,2	,"36 boxes",	21.3500	,	0	,	0	,	0	,	1	)
    addProduct(db,"Grandma's Boysenberry Spread",	3,2	,"12 - 8 oz jars",	25.0000	,	120	,	0	,	25	,	0	)
    addProduct(db,"Uncle Bob's Organic Dried Pears",	3,7	,"12 - 1 lb pkgs.",	30.0000	,	15	,	0	,	10	,	0	)
    addProduct(db,"Northwoods Cranberry Sauce",	3,2	,"12 - 12 oz jars",	40.0000	,	6	,	0	,	0	,	0	)
    addProduct(db,"Mishi Kobe Niku",	4,6	,"18 - 500 g pkgs.",	97.0000	,	29	,	0	,	0	,	1	)
    addProduct(db,"Ikura",	4,8	,"12 - 200 ml jars",	31.0000	,	31	,	0	,	0	,	0	)
    addProduct(db,"Queso Cabrales",	5,4	,"1 kg pkg.",	21.0000	,	22	,	30	,	30	,	0	)
    addProduct(db,"Queso Manchego La Pastora",	5,4	,"10 - 500 g pkgs.",	38.0000	,	86	,	0	,	0	,	0	)
    addProduct(db,"Konbu",	6,8	,"2 kg box",	6.0000	,	24	,	0	,	5	,	0	)
    addProduct(db,"Tofu",	6,7	,"40 - 100 g pkgs.",	23.2500	,	35	,	0	,	0	,	0	)
    addProduct(db,"Genen Shouyu",	6,2	,"24 - 250 ml bottles",	15.5000	,	39	,	0	,	5	,	0	)
    addProduct(db,"Pavlova",	7,3	,"32 - 500 g boxes",	17.4500	,	29	,	0	,	10	,	0	)
    addProduct(db,"Alice Mutton",	7,6	,"20 - 1 kg tins",	39.0000	,	0	,	0	,	0	,	1	)
    addProduct(db,"Carnarvon Tigers",	7,8	,"16 kg pkg.",	62.5000	,	42	,	0	,	0	,	0	)
    addProduct(db,"Teatime Chocolate Biscuits",	8,3	,"10 boxes x 12 pieces",	9.2000	,	25	,	0	,	5	,	0	)
    addProduct(db,"Sir Rodney's Marmalade",	8,3	,"30 gift boxes",	81.0000	,	40	,	0	,	0	,	0	)
    addProduct(db,"Sir Rodney's Scones",	8,3	,"24 pkgs. x 4 pieces",	10.0000	,	3	,	40	,	5	,	0	)
    addProduct(db,"Gustaf's Knckebrd",	9,5	,"24 - 500 g pkgs.",	21.0000	,	104	,	0	,	25	,	0	)
    addProduct(db,"Tunnbrd",	9,5	,"12 - 250 g pkgs.",	9.0000	,	61	,	0	,	25	,	0	)
    addProduct(db,"Guaran Fantstica",	10,1	,"12 - 355 ml cans",	4.5000	,	20	,	0	,	0	,	1	)
    addProduct(db,"NuNuCa Nu-Nougat-Creme",	11,3	,"20 - 450 g glasses",	14.0000	,	76	,	0	,	30	,	0	)
    addProduct(db,"Gumbr Gummibrchen",	11,3	,"100 - 250 g bags",	31.2300	,	15	,	0	,	0	,	0	)
    addProduct(db,"Schoggi Schokolade",	11,3	,"100 - 100 g pieces",	43.9000	,	49	,	0	,	30	,	0	)
    addProduct(db,"Rssle Sauerkraut",	12,7	,"25 - 825 g cans",	45.6000	,	26	,	0	,	0	,	1	)
    addProduct(db,"Thringer Rostbratwurst",	12,6	,"50 bags x 30 sausgs.",	123.7900	,	0	,	0	,	0	,	1	)
    addProduct(db,"Nord-Ost Matjeshering",	13,8	,"10 - 200 g glasses",	25.8900	,	10	,	0	,	15	,	0	)
    addProduct(db,"Gorgonzola Telino",	14,4	,"12 - 100 g pkgs",	12.5000	,	0	,	70	,	20	,	0	)
    addProduct(db,"Mascarpone Fabioli",	14,4	,"24 - 200 g pkgs.",	32.0000	,	9	,	40	,	25	,	0	)
    addProduct(db,"Geitost",	15,4	,"500 g",	2.5000	,	112	,	0	,	20	,	0	)
    addProduct(db,"Sasquatch Ale",	16,1	,"24 - 12 oz bottles",	14.0000	,	111	,	0	,	15	,	0	)
    addProduct(db,"Steeleye Stout",	16,1	,"24 - 12 oz bottles",	18.0000	,	20	,	0	,	15	,	0	)
    addProduct(db,"Inlagd Sill",	17,8	,"24 - 250 g  jars",	19.0000	,	112	,	0	,	20	,	0	)
    addProduct(db,"Gravad lax",	17,8	,"12 - 500 g pkgs.",	26.0000	,	11	,	50	,	25	,	0	)
    addProduct(db,"Cte de Blaye",	18,1	,"12 - 75 cl bottles",	263.5000	,	17	,	0	,	15	,	0	)
    addProduct(db,"Chartreuse verte",	18,1	,"750 cc per bottle",	18.0000	,	69	,	0	,	5	,	0	)
    addProduct(db,"Boston Crab Meat",	19,8	,"24 - 4 oz tins",	18.4000	,	123	,	0	,	30	,	0	)
    addProduct(db,"Jack's New England Clam Chowder",	19,8	,"12 - 12 oz cans",	9.6500	,	85	,	0	,	10	,	0	)
    addProduct(db,"Singaporean Hokkien Fried Mee",	20,5	,"32 - 1 kg pkgs.",	14.0000	,	26	,	0	,	0	,	1	)
    addProduct(db,"Ipoh Coffee",	20,1	,"16 - 500 g tins",	46.0000	,	17	,	10	,	25	,	0	)
    addProduct(db,"Gula Malacca",	20,2	,"20 - 2 kg bags",	19.4500	,	27	,	0	,	15	,	0	)
    addProduct(db,"Rogede sild",	21,8	,"1k pkg.",	9.5000	,	5	,	70	,	15	,	0	)
    addProduct(db,"Spegesild",	21,8	,"4 - 450 g glasses",	12.0000	,	95	,	0	,	0	,	0	)
    addProduct(db,"Zaanse koeken",	22,3	,"10 - 4 oz boxes",	9.5000	,	36	,	0	,	0	,	0	)
    addProduct(db,"Chocolade",	22,3	,"10 pkgs.",	12.7500	,	15	,	70	,	25	,	0	)
    addProduct(db,"Maxilaku",	23,3	,"24 - 50 g pkgs.",	20.0000	,	10	,	60	,	15	,	0	)
    addProduct(db,"Valkoinen suklaa",	23,3	,"12 - 100 g bars",	16.2500	,	65	,	0	,	30	,	0	)
    addProduct(db,"Manjimup Dried Apples",	24,7	,"50 - 300 g pkgs.",	53.0000	,	20	,	0	,	10	,	0	)
    addProduct(db,"Filo Mix",	24,5	,"16 - 2 kg boxes",	7.0000	,	38	,	0	,	25	,	0	)
    addProduct(db,"Perth Pasties",	24,6	,"48 pieces",	32.8000	,	0	,	0	,	0	,	1	)
    addProduct(db,"Tourtire",	25,6	,"16 pies",	7.4500	,	21	,	0	,	10	,	0	)
    addProduct(db,"Pt chinois",	25,6	,"24 boxes x 2 pies",	24.0000	,	115	,	0	,	20	,	0	)
    addProduct(db,"Gnocchi di nonna Alice",	26,5	,"24 - 250 g pkgs.",	38.0000	,	21	,	10	,	30	,	0	)
    addProduct(db,"Ravioli Angelo",	26,5	,"24 - 250 g pkgs.",	19.5000	,	36	,	0	,	20	,	0	)
    addProduct(db,"Escargots de Bourgogne",	27,8	,"24 pieces",	13.2500	,	62	,	0	,	20	,	0	)
    addProduct(db,"Raclette Courdavault",	28,4	,"5 kg pkg.",	55.0000	,	79	,	0	,	0	,	0	)
    addProduct(db,"Camembert Pierrot",	28,4	,"15 - 300 g rounds",	34.0000	,	19	,	0	,	0	,	0	)
    addProduct(db,"Sirop d'rable",	29,2	,"24 - 500 ml bottles",	28.5000	,	113	,	0	,	25	,	0	)
    addProduct(db,"Tarte au sucre",	29,3	,"48 pies",	49.3000	,	17	,	0	,	0	,	0	)
    addProduct(db,"Vegie-spread",	7,2	,"15 - 625 g jars",	43.9000	,	24	,	0	,	5	,	0	)
    addProduct(db,"Wimmers gute Semmelkndel",	12,5	,"20 bags x 4 pieces",	33.2500	,	22	,	80	,	30	,	0	)
    addProduct(db,"Louisiana Fiery Hot Pepper Sauce",	2,2	,"32 - 8 oz bottles",	21.0500	,	76	,	0	,	0	,	0	)
    addProduct(db,"Louisiana Hot Spiced Okra",	2,2	,"24 - 8 oz jars",	17.0000	,	4	,	100	,	20	,	0	)
    addProduct(db,"Laughing Lumberjack Lager",	16,1	,"24 - 12 oz bottles",	14.0000	,	52	,	0	,	10	,	0	)
    addProduct(db,"Scottish Longbreads",	8,3	,"10 boxes x 8 pieces",	12.5000	,	6	,	10	,	15	,	0	)
    addProduct(db,"Gudbrandsdalsost",	15,4	,"10 kg pkg.",	36.0000	,	26	,	0	,	15	,	0	)
    addProduct(db,"Outback Lager",	7,1	,"24 - 355 ml bottles",	15.0000	,	15	,	10	,	30	,	0	)
    addProduct(db,"Flotemysost",	15,4	,"10 - 500 g pkgs.",	21.5000	,	26	,	0	,	0	,	0	)
    addProduct(db,"Mozzarella di Giovanni",	14,4	,"24 - 200 g pkgs.",	34.8000	,	14	,	0	,	0	,	0	)
    addProduct(db,"Rd Kaviar",	17,8	,"24 - 150 g jars",	15.0000	,	101	,	0	,	5	,	0	)
    addProduct(db,"Longlife Tofu",	4,7	,"5 kg pkg.",	10.0000	,	4	,	20	,	5	,	0	)
    addProduct(db,"Rhnbru Klosterbier",	12,1	,"24 - 0.5 l bottles",	7.7500	,	125	,	0	,	25	,	0	)
    addProduct(db,"Lakkalikri",	23,1	,"500 ml",	18.0000	,	57	,	0	,	20	,	0	)
    addProduct(db,"Original Frankfurter grne Soe",	12,2	,"12 boxes",	13.0000	,	32	,	0	,	15	,	0	)
    addProduct(db,"Handdesinfektion",	1,1	,"1",	12.0000	,	2	,	0	,	0	,	0	)

    add_subscribers()
    add_newletter()

def mapNorthwindCategporyIdToThisDb(db: SQLAlchemy, northwind_category__id: int) -> int|None:
    name = ""
    if northwind_category__id == 1:
        name = "Beverages"
    if northwind_category__id == 2:
        name = "Condiments"
    if northwind_category__id == 3:
        name = "Confections"
    if northwind_category__id == 4:
        name = "Dairy Products"
    if northwind_category__id == 5:
        name = "Grains/Cereals"
    if northwind_category__id == 6:
        name = "Meat/Poultry"
    if northwind_category__id == 7:
        name = "Produce"
    if northwind_category__id == 8:
        name = "Seafood"

    stmt = select(Category.CategoryID).where(Category.CategoryName == name)
    result = db.session.execute(stmt).scalar()  # Use scalar() to get a single value
    return result
    

def addProduct(db: SQLAlchemy,
               name: str,
               supplier_id: int,
               category_id: int,
               quantity_per_unit: str,
               unit_price: float,
               units_in_stock: int,
               units_on_order: int,
               reorder_level: int,
               discontinued: int
               ) -> None:
    stmt = select(Product).where(Product.ProductName == name)
    a = db.session.execute(stmt).first()
    if a == None:
        c = Product()
        c.ProductName = name
        c.SupplierID = supplier_id
        c.CategoryId = mapNorthwindCategporyIdToThisDb(db, category_id)
        c.QuantityPerUnit = quantity_per_unit
        c.UnitPrice = unit_price
        c.UnitsInStock = units_in_stock
        c.UnitsOnOrder = units_on_order
        c.ReorderLevel = reorder_level
        c.Discontinued = discontinued

        db.session.add(c)
        db.session.commit()

def addCat(db: SQLAlchemy, name: str, description: str) -> None:
    stmt = select(Category).where(Category.CategoryName == name)
    a = db.session.execute(stmt).first()
    if a ==  None:
        c = Category()
        c.CategoryName = name
        c.Description = description
        db.session.add(c)
        db.session.commit()

def AddRoleIfNotExists(name: str) -> None:
    stmt = select(Role).where(Role.name == name)
    if db.session.execute(stmt).first():
        return
    role = Role()
    role.name = name
    db.session.add(role)
    db.session.commit()

def add_subscribers(minium_count: int = 3) -> None:
    stmt = select(func.count()).select_from(Subscriber)
    subscriber_count = db.session.execute(stmt).scalar()
    if subscriber_count < minium_count:
        adding = minium_count - subscriber_count
        for _ in range(adding):
            subscriber = Subscriber()
            subscriber.email = barnum.create_email()
            subscriber.active = True
            db.session.add(subscriber)
        db.session.commit()

def add_newletter() -> None:
    stmt = select(func.count()).select_from(Newsletter)
    newsletter_count = db.session.execute(stmt).scalar()
    if newsletter_count < 1:
        newsletter = Newsletter()
        newsletter.subject = 'A sample newsletter'
        newsletter.content = 'This is a sample newsletter generated to test out the system.'
        newsletter.last_edit = datetime.strptime('2024-02-13 10:15', '%Y-%m-%d %H:%M')
        newsletter.is_sent = False
        db.session.add(newsletter)
        db.session.commit()