from datetime import datetime
from flask import flash
from flask_mail import Message
from sqlalchemy import select
from werkzeug.datastructures import ImmutableMultiDict

from extensions import mail
from models import Newsletter, Subscriber, db

def get_all_newsletter() -> list[Newsletter]:
    stmt = select(Newsletter)
    return db.session.execute(stmt).scalars().all()

def create_newsletter() -> Newsletter:
    newsletter = Newsletter()
    newsletter.subject = 'New subject'
    newsletter.content = 'New content'
    newsletter.last_edit = datetime.now()
    newsletter.is_sent = False
    db.session.add(newsletter)
    db.session.commit()
    return newsletter.id

def update_newsletter(newsletter: Newsletter, edit_newsletter_form: ImmutableMultiDict) -> None:
    newsletter.subject = edit_newsletter_form['subject']
    newsletter.content = edit_newsletter_form['content']
    newsletter.last_edit = datetime.now()
    db.session.add(newsletter)
    db.session.commit()

def get_newsletter(newsletter_id: int) -> Newsletter|None:
    if not newsletter_id:
        return None
    stmt = select(Newsletter).where(Newsletter.id == newsletter_id)
    return db.session.execute(stmt).scalar()

def send_newsletter(newsletter_id: int) -> None:
    stmt = select(Newsletter).where(Newsletter.id == newsletter_id)
    newsletter = db.session.execute(stmt).scalar()
    if not newsletter:
        flash(f'Newsletter #{newsletter_id} not found', 'error')
        return
    if newsletter.is_sent:
        flash(f'Newsletter #{newsletter_id} already sent', 'warning')
    else:
        stmt = select(Subscriber.email).where(Subscriber.active)
        active_subscriber_emails = db.session.execute(stmt).scalars().all()
        with mail.connect() as conn:
            for email in active_subscriber_emails:
                msg = Message(recipients = [email],
                              body = newsletter.content,
                              subject = newsletter.subject
                              )
                conn.send(msg)
        newsletter.date_sent = datetime.now()
        newsletter.is_sent = True
        db.session.add(newsletter)
        db.session.commit()
        flash(f'Newsletter #{newsletter_id} sent', 'message')
    
def get_newsletters_for_page(page, per_page):
 
    newsletters = Newsletter.query.paginate(page=page, per_page=per_page)
    return newsletters