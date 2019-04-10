from flask import render_template, url_for, flash, jsonify, redirect, request, abort, flash
from music import app, mongo

enduser = mongo.db.endusers
uploads = mongo.db.uploads

@app.route('/admin_home')
def admin_home():
	return render_template('admin/index.html')

@app.route('/admin_get_user_list')
def admin_get_user_list():
	userlist = enduser.find({'role': None})
	return jsonify({'status': 'success', 'message': 'Successfully Listed', 'content': tuple(userlist)})

@app.route('/admin_get_artist_list')
def admin_get_artist_list():
	artistlist = enduser.find({'role':{'$ne':None}})
	return jsonify({'status': 'success', 'message': 'Successfully Listed', 'content': tuple(artistlist)})

@app.route('/admin_approve_artist')
def admin_approve_artist():
	approvelist = enduser.find({'isapproved': False, 'role':{'$ne':None}})
	return jsonify({'status': 'success', 'message': 'Successfully Listed', 'content': tuple(approvelist)})

@app.route('/admin_get_file_list')
def admin_get_file_list():
	filelist = uploads.find()
	return jsonify({'status': 'success', 'message': 'Successfully Listed', 'content': tuple(filelist)})

