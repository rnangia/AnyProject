import React from 'react';
import ReactDOM from 'react-dom';
import { AppContainer } from 'react-hot-loader';
import { Provider } from 'react-redux';

import App from './routes';
import { configure } from './store';

// require('./stylesheets/main.scss');

const store = configure();

const noHoist = {};

const render = Component => {
	ReactDOM.render(
		<AppContainer {...noHoist}>
			<Component store={store}/>
		</AppContainer>,
		document.getElementById('content')
	);
};

render(App);


if (module.hot) {
	module.hot.accept('./routes', render);
}
