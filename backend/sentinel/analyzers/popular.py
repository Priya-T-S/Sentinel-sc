"""Reference lists of widely used package names, used ONLY for typosquat similarity checks.

These are well-known, high-download packages. Similarity to one of them is a weak signal
on its own; it is combined with other evidence before anything is called suspicious.
"""

NPM_POPULAR = """
lodash react react-dom express axios moment chalk commander debug request async underscore uuid
vue jquery webpack typescript babel-core @babel/core eslint prettier jest mocha chai sinon yargs
minimist glob rimraf mkdirp fs-extra bluebird q colors body-parser cookie-parser cors dotenv
mongoose mongodb mysql mysql2 pg redis ioredis sequelize knex socket.io ws node-fetch got
superagent cheerio puppeteer jsonwebtoken bcrypt bcryptjs passport helmet morgan winston pino
nodemon pm2 dayjs date-fns classnames prop-types redux react-redux react-router react-router-dom
next nuxt angular rxjs zone.js core-js regenerator-runtime tslib semver inquirer ora boxen
yeoman-generator gulp grunt browserify rollup vite esbuild postcss autoprefixer sass less
tailwindcss styled-components emotion immutable ramda validator joi yup zod ajv qs cookie
path-to-regexp send serve-static finalhandler mime mime-types on-finished statuses http-errors
depd destroy etag fresh range-parser content-type raw-body iconv-lite safe-buffer string_decoder
readable-stream inherits util-deprecate isarray once wrappy graceful-fs follow-redirects
form-data combined-stream asynckit delayed-stream proxy-from-env cross-env cross-spawn
shelljs execa chokidar nanoid ms escape-html lru-cache yaml js-yaml xml2js handlebars ejs pug
mustache marked highlight.js node-sass sharp jimp canvas electron eventemitter3 event-stream
coffee-script left-pad is-number is-promise kind-of ua-parser-js coa rc colors faker
""".split()

PYPI_POPULAR = """
requests urllib3 boto3 botocore setuptools certifi idna charset-normalizer numpy pandas
python-dateutil six pyyaml s3transfer typing-extensions wheel pip cryptography packaging
jmespath pyasn1 rsa attrs google-api-core protobuf importlib-metadata zipp click jinja2
markupsafe pytz pyparsing cffi pycparser wrapt cachetools werkzeug flask django fastapi
uvicorn starlette pydantic sqlalchemy psycopg2 psycopg2-binary pymysql redis celery kombu
scipy scikit-learn matplotlib seaborn tensorflow torch keras pillow opencv-python lxml
beautifulsoup4 soupsieve html5lib aiohttp yarl multidict frozenlist aiosignal async-timeout
httpx httpcore anyio sniffio h11 grpcio grpcio-tools googleapis-common-protos pytest
pluggy iniconfig coverage tox virtualenv filelock platformdirs distlib black isort flake8
pylint mypy toml tomli colorama tqdm rich docutils sphinx paramiko pynacl bcrypt
pyjwt oauthlib requests-oauthlib python-dotenv gunicorn openpyxl xlrd tabulate
decorator networkx sympy simplejson ujson orjson msgpack dill cloudpickle joblib
""".split()

POPULAR = {"npm": set(NPM_POPULAR), "PyPI": set(PYPI_POPULAR)}
