from music import app


if __name__ == "__main__":

	# if not app.config['DB_CREATED']:
		# db.create_all()

	app.run(
		host=app.config['HOST'], 
		port=app.config['PORT'],
		debug=app.config['DEBUG'],
		use_reloader=app.config['USE_RELOADER'])