// This file can be replaced during build by using the `fileReplacements` array.
// `ng build --prod` replaces `environment.ts` with `environment.prod.ts`.
// The list of file replacements can be found in `angular.json`.

export const environment = {
  production: false,
  api: {
    server: 'http://65.0.170.173:3000/',
    mapKey: '9cdbc94d-1c1e-4f37-a830-b19593c04b26',
    googleAuthClientId: 'VIKRL2JQUc5G9nsu',
    webSocketUrl: "ws://65.0.170.173:3000/websocket"
  }
};

/*
 * For easier debugging in development mode, you can import the following file
 * to ignore zone related error stack frames such as `zone.run`, `zoneDelegate.invokeTask`.
 *
 * This import should be commented out in production mode because it will have a negative impact
 * on performance if an error is thrown.
 */
// import 'zone.js/dist/zone-error';  // Included with Angular CLI.
