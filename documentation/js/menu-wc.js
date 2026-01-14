'use strict';

customElements.define('compodoc-menu', class extends HTMLElement {
    constructor() {
        super();
        this.isNormalMode = this.getAttribute('mode') === 'normal';
    }

    connectedCallback() {
        this.render(this.isNormalMode);
    }

    render(isNormalMode) {
        let tp = lithtml.html(`
        <nav>
            <ul class="list">
                <li class="title">
                    <a href="index.html" data-type="index-link">silah-backend documentation</a>
                </li>

                <li class="divider"></li>
                ${ isNormalMode ? `<div id="book-search-input" role="search"><input type="text" placeholder="Type to search"></div>` : '' }
                <li class="chapter">
                    <a data-type="chapter-link" href="index.html"><span class="icon ion-ios-home"></span>Getting started</a>
                    <ul class="links">
                                <li class="link">
                                    <a href="overview.html" data-type="chapter-link">
                                        <span class="icon ion-ios-keypad"></span>Overview
                                    </a>
                                </li>

                            <li class="link">
                                <a href="index.html" data-type="chapter-link">
                                    <span class="icon ion-ios-paper"></span>
                                        README
                                </a>
                            </li>
                                <li class="link">
                                    <a href="dependencies.html" data-type="chapter-link">
                                        <span class="icon ion-ios-list"></span>Dependencies
                                    </a>
                                </li>
                                <li class="link">
                                    <a href="properties.html" data-type="chapter-link">
                                        <span class="icon ion-ios-apps"></span>Properties
                                    </a>
                                </li>

                    </ul>
                </li>
                    <li class="chapter modules">
                        <a data-type="chapter-link" href="modules.html">
                            <div class="menu-toggler linked" data-bs-toggle="collapse" ${ isNormalMode ?
                                'data-bs-target="#modules-links"' : 'data-bs-target="#xs-modules-links"' }>
                                <span class="icon ion-ios-archive"></span>
                                <span class="link-name">Modules</span>
                                <span class="icon ion-ios-arrow-down"></span>
                            </div>
                        </a>
                        <ul class="links collapse " ${ isNormalMode ? 'id="modules-links"' : 'id="xs-modules-links"' }>
                            <li class="link">
                                <a href="modules/AnalyticsModule.html" data-type="entity-link" >AnalyticsModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                            'data-bs-target="#controllers-links-module-AnalyticsModule-6aa0829d3feb4d3f8d259ed55b77867e6250d4a59fda9a340d530142de4c27894a6dfdbe13209b143320c43130e7b308527caaf54836d94ff39ad5f9db0a6951"' : 'data-bs-target="#xs-controllers-links-module-AnalyticsModule-6aa0829d3feb4d3f8d259ed55b77867e6250d4a59fda9a340d530142de4c27894a6dfdbe13209b143320c43130e7b308527caaf54836d94ff39ad5f9db0a6951"' }>
                                            <span class="icon ion-md-swap"></span>
                                            <span>Controllers</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="controllers-links-module-AnalyticsModule-6aa0829d3feb4d3f8d259ed55b77867e6250d4a59fda9a340d530142de4c27894a6dfdbe13209b143320c43130e7b308527caaf54836d94ff39ad5f9db0a6951"' :
                                            'id="xs-controllers-links-module-AnalyticsModule-6aa0829d3feb4d3f8d259ed55b77867e6250d4a59fda9a340d530142de4c27894a6dfdbe13209b143320c43130e7b308527caaf54836d94ff39ad5f9db0a6951"' }>
                                            <li class="link">
                                                <a href="controllers/AnalyticsController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >AnalyticsController</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-AnalyticsModule-6aa0829d3feb4d3f8d259ed55b77867e6250d4a59fda9a340d530142de4c27894a6dfdbe13209b143320c43130e7b308527caaf54836d94ff39ad5f9db0a6951"' : 'data-bs-target="#xs-injectables-links-module-AnalyticsModule-6aa0829d3feb4d3f8d259ed55b77867e6250d4a59fda9a340d530142de4c27894a6dfdbe13209b143320c43130e7b308527caaf54836d94ff39ad5f9db0a6951"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-AnalyticsModule-6aa0829d3feb4d3f8d259ed55b77867e6250d4a59fda9a340d530142de4c27894a6dfdbe13209b143320c43130e7b308527caaf54836d94ff39ad5f9db0a6951"' :
                                        'id="xs-injectables-links-module-AnalyticsModule-6aa0829d3feb4d3f8d259ed55b77867e6250d4a59fda9a340d530142de4c27894a6dfdbe13209b143320c43130e7b308527caaf54836d94ff39ad5f9db0a6951"' }>
                                        <li class="link">
                                            <a href="injectables/AnalyticsService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >AnalyticsService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/AppModule.html" data-type="entity-link" >AppModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                            'data-bs-target="#controllers-links-module-AppModule-df4db42888c220f532c11c57910d93d08922a085ffea44d20d3dff69ab99a95f1ad0eee8ff878b16b7dca642111886c395fdba514eb372fd0655cebe6228666b"' : 'data-bs-target="#xs-controllers-links-module-AppModule-df4db42888c220f532c11c57910d93d08922a085ffea44d20d3dff69ab99a95f1ad0eee8ff878b16b7dca642111886c395fdba514eb372fd0655cebe6228666b"' }>
                                            <span class="icon ion-md-swap"></span>
                                            <span>Controllers</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="controllers-links-module-AppModule-df4db42888c220f532c11c57910d93d08922a085ffea44d20d3dff69ab99a95f1ad0eee8ff878b16b7dca642111886c395fdba514eb372fd0655cebe6228666b"' :
                                            'id="xs-controllers-links-module-AppModule-df4db42888c220f532c11c57910d93d08922a085ffea44d20d3dff69ab99a95f1ad0eee8ff878b16b7dca642111886c395fdba514eb372fd0655cebe6228666b"' }>
                                            <li class="link">
                                                <a href="controllers/AppController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >AppController</a>
                                            </li>
                                            <li class="link">
                                                <a href="controllers/HealthController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >HealthController</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-AppModule-df4db42888c220f532c11c57910d93d08922a085ffea44d20d3dff69ab99a95f1ad0eee8ff878b16b7dca642111886c395fdba514eb372fd0655cebe6228666b"' : 'data-bs-target="#xs-injectables-links-module-AppModule-df4db42888c220f532c11c57910d93d08922a085ffea44d20d3dff69ab99a95f1ad0eee8ff878b16b7dca642111886c395fdba514eb372fd0655cebe6228666b"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-AppModule-df4db42888c220f532c11c57910d93d08922a085ffea44d20d3dff69ab99a95f1ad0eee8ff878b16b7dca642111886c395fdba514eb372fd0655cebe6228666b"' :
                                        'id="xs-injectables-links-module-AppModule-df4db42888c220f532c11c57910d93d08922a085ffea44d20d3dff69ab99a95f1ad0eee8ff878b16b7dca642111886c395fdba514eb372fd0655cebe6228666b"' }>
                                        <li class="link">
                                            <a href="injectables/AppService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >AppService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/AuthModule.html" data-type="entity-link" >AuthModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                            'data-bs-target="#controllers-links-module-AuthModule-dab9926dee2831f473a092b8045f3b5f34b12d13a45103824f8bd6a68ff83a9b3f45989f1efbdf848a22f73ec4256d0ead8cc2d5f7d64f8abcc9e050a38da993"' : 'data-bs-target="#xs-controllers-links-module-AuthModule-dab9926dee2831f473a092b8045f3b5f34b12d13a45103824f8bd6a68ff83a9b3f45989f1efbdf848a22f73ec4256d0ead8cc2d5f7d64f8abcc9e050a38da993"' }>
                                            <span class="icon ion-md-swap"></span>
                                            <span>Controllers</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="controllers-links-module-AuthModule-dab9926dee2831f473a092b8045f3b5f34b12d13a45103824f8bd6a68ff83a9b3f45989f1efbdf848a22f73ec4256d0ead8cc2d5f7d64f8abcc9e050a38da993"' :
                                            'id="xs-controllers-links-module-AuthModule-dab9926dee2831f473a092b8045f3b5f34b12d13a45103824f8bd6a68ff83a9b3f45989f1efbdf848a22f73ec4256d0ead8cc2d5f7d64f8abcc9e050a38da993"' }>
                                            <li class="link">
                                                <a href="controllers/AuthController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >AuthController</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-AuthModule-dab9926dee2831f473a092b8045f3b5f34b12d13a45103824f8bd6a68ff83a9b3f45989f1efbdf848a22f73ec4256d0ead8cc2d5f7d64f8abcc9e050a38da993"' : 'data-bs-target="#xs-injectables-links-module-AuthModule-dab9926dee2831f473a092b8045f3b5f34b12d13a45103824f8bd6a68ff83a9b3f45989f1efbdf848a22f73ec4256d0ead8cc2d5f7d64f8abcc9e050a38da993"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-AuthModule-dab9926dee2831f473a092b8045f3b5f34b12d13a45103824f8bd6a68ff83a9b3f45989f1efbdf848a22f73ec4256d0ead8cc2d5f7d64f8abcc9e050a38da993"' :
                                        'id="xs-injectables-links-module-AuthModule-dab9926dee2831f473a092b8045f3b5f34b12d13a45103824f8bd6a68ff83a9b3f45989f1efbdf848a22f73ec4256d0ead8cc2d5f7d64f8abcc9e050a38da993"' }>
                                        <li class="link">
                                            <a href="injectables/AuthService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >AuthService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/BidModule.html" data-type="entity-link" >BidModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                            'data-bs-target="#controllers-links-module-BidModule-e44f91238e63727de5daca8cbabfe45dfffe88c6a584517e1bb0f1de1136204eeef8d3ab0da1a19a33261f031760806e366313dddd364a8606d78fcc509a28e0"' : 'data-bs-target="#xs-controllers-links-module-BidModule-e44f91238e63727de5daca8cbabfe45dfffe88c6a584517e1bb0f1de1136204eeef8d3ab0da1a19a33261f031760806e366313dddd364a8606d78fcc509a28e0"' }>
                                            <span class="icon ion-md-swap"></span>
                                            <span>Controllers</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="controllers-links-module-BidModule-e44f91238e63727de5daca8cbabfe45dfffe88c6a584517e1bb0f1de1136204eeef8d3ab0da1a19a33261f031760806e366313dddd364a8606d78fcc509a28e0"' :
                                            'id="xs-controllers-links-module-BidModule-e44f91238e63727de5daca8cbabfe45dfffe88c6a584517e1bb0f1de1136204eeef8d3ab0da1a19a33261f031760806e366313dddd364a8606d78fcc509a28e0"' }>
                                            <li class="link">
                                                <a href="controllers/BidController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >BidController</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-BidModule-e44f91238e63727de5daca8cbabfe45dfffe88c6a584517e1bb0f1de1136204eeef8d3ab0da1a19a33261f031760806e366313dddd364a8606d78fcc509a28e0"' : 'data-bs-target="#xs-injectables-links-module-BidModule-e44f91238e63727de5daca8cbabfe45dfffe88c6a584517e1bb0f1de1136204eeef8d3ab0da1a19a33261f031760806e366313dddd364a8606d78fcc509a28e0"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-BidModule-e44f91238e63727de5daca8cbabfe45dfffe88c6a584517e1bb0f1de1136204eeef8d3ab0da1a19a33261f031760806e366313dddd364a8606d78fcc509a28e0"' :
                                        'id="xs-injectables-links-module-BidModule-e44f91238e63727de5daca8cbabfe45dfffe88c6a584517e1bb0f1de1136204eeef8d3ab0da1a19a33261f031760806e366313dddd364a8606d78fcc509a28e0"' }>
                                        <li class="link">
                                            <a href="injectables/BidCronService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >BidCronService</a>
                                        </li>
                                        <li class="link">
                                            <a href="injectables/BidService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >BidService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/BuyerModule.html" data-type="entity-link" >BuyerModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                            'data-bs-target="#controllers-links-module-BuyerModule-b4a9b9f00b009678e8dd17c14ad81f7296aa4e0159ed22a77e4fc6c71dcf792798d93de36dc89a954ad5bd456665ed97a4820df2211a5df69b69e0f0107ea263"' : 'data-bs-target="#xs-controllers-links-module-BuyerModule-b4a9b9f00b009678e8dd17c14ad81f7296aa4e0159ed22a77e4fc6c71dcf792798d93de36dc89a954ad5bd456665ed97a4820df2211a5df69b69e0f0107ea263"' }>
                                            <span class="icon ion-md-swap"></span>
                                            <span>Controllers</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="controllers-links-module-BuyerModule-b4a9b9f00b009678e8dd17c14ad81f7296aa4e0159ed22a77e4fc6c71dcf792798d93de36dc89a954ad5bd456665ed97a4820df2211a5df69b69e0f0107ea263"' :
                                            'id="xs-controllers-links-module-BuyerModule-b4a9b9f00b009678e8dd17c14ad81f7296aa4e0159ed22a77e4fc6c71dcf792798d93de36dc89a954ad5bd456665ed97a4820df2211a5df69b69e0f0107ea263"' }>
                                            <li class="link">
                                                <a href="controllers/BuyerController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >BuyerController</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-BuyerModule-b4a9b9f00b009678e8dd17c14ad81f7296aa4e0159ed22a77e4fc6c71dcf792798d93de36dc89a954ad5bd456665ed97a4820df2211a5df69b69e0f0107ea263"' : 'data-bs-target="#xs-injectables-links-module-BuyerModule-b4a9b9f00b009678e8dd17c14ad81f7296aa4e0159ed22a77e4fc6c71dcf792798d93de36dc89a954ad5bd456665ed97a4820df2211a5df69b69e0f0107ea263"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-BuyerModule-b4a9b9f00b009678e8dd17c14ad81f7296aa4e0159ed22a77e4fc6c71dcf792798d93de36dc89a954ad5bd456665ed97a4820df2211a5df69b69e0f0107ea263"' :
                                        'id="xs-injectables-links-module-BuyerModule-b4a9b9f00b009678e8dd17c14ad81f7296aa4e0159ed22a77e4fc6c71dcf792798d93de36dc89a954ad5bd456665ed97a4820df2211a5df69b69e0f0107ea263"' }>
                                        <li class="link">
                                            <a href="injectables/BuyerService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >BuyerService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/CartModule.html" data-type="entity-link" >CartModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                            'data-bs-target="#controllers-links-module-CartModule-d410da101387ccd8e482020de29214138059ac4fd7b686a3d2552e5988831ee8227bd7c45eb4923a7811d8248621fa2e436febd1283b90f1792e185f769bf5aa"' : 'data-bs-target="#xs-controllers-links-module-CartModule-d410da101387ccd8e482020de29214138059ac4fd7b686a3d2552e5988831ee8227bd7c45eb4923a7811d8248621fa2e436febd1283b90f1792e185f769bf5aa"' }>
                                            <span class="icon ion-md-swap"></span>
                                            <span>Controllers</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="controllers-links-module-CartModule-d410da101387ccd8e482020de29214138059ac4fd7b686a3d2552e5988831ee8227bd7c45eb4923a7811d8248621fa2e436febd1283b90f1792e185f769bf5aa"' :
                                            'id="xs-controllers-links-module-CartModule-d410da101387ccd8e482020de29214138059ac4fd7b686a3d2552e5988831ee8227bd7c45eb4923a7811d8248621fa2e436febd1283b90f1792e185f769bf5aa"' }>
                                            <li class="link">
                                                <a href="controllers/CartController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >CartController</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-CartModule-d410da101387ccd8e482020de29214138059ac4fd7b686a3d2552e5988831ee8227bd7c45eb4923a7811d8248621fa2e436febd1283b90f1792e185f769bf5aa"' : 'data-bs-target="#xs-injectables-links-module-CartModule-d410da101387ccd8e482020de29214138059ac4fd7b686a3d2552e5988831ee8227bd7c45eb4923a7811d8248621fa2e436febd1283b90f1792e185f769bf5aa"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-CartModule-d410da101387ccd8e482020de29214138059ac4fd7b686a3d2552e5988831ee8227bd7c45eb4923a7811d8248621fa2e436febd1283b90f1792e185f769bf5aa"' :
                                        'id="xs-injectables-links-module-CartModule-d410da101387ccd8e482020de29214138059ac4fd7b686a3d2552e5988831ee8227bd7c45eb4923a7811d8248621fa2e436febd1283b90f1792e185f769bf5aa"' }>
                                        <li class="link">
                                            <a href="injectables/CartService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >CartService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/CategoryModule.html" data-type="entity-link" >CategoryModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                            'data-bs-target="#controllers-links-module-CategoryModule-878dc34b35bce521bac3afa01fe378c5828f18d16fd2c53c122f442cd7ece2672d6824b975f57e99210d812dc6f178c451a3679c4b370ea04a6b86149d7d1acf"' : 'data-bs-target="#xs-controllers-links-module-CategoryModule-878dc34b35bce521bac3afa01fe378c5828f18d16fd2c53c122f442cd7ece2672d6824b975f57e99210d812dc6f178c451a3679c4b370ea04a6b86149d7d1acf"' }>
                                            <span class="icon ion-md-swap"></span>
                                            <span>Controllers</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="controllers-links-module-CategoryModule-878dc34b35bce521bac3afa01fe378c5828f18d16fd2c53c122f442cd7ece2672d6824b975f57e99210d812dc6f178c451a3679c4b370ea04a6b86149d7d1acf"' :
                                            'id="xs-controllers-links-module-CategoryModule-878dc34b35bce521bac3afa01fe378c5828f18d16fd2c53c122f442cd7ece2672d6824b975f57e99210d812dc6f178c451a3679c4b370ea04a6b86149d7d1acf"' }>
                                            <li class="link">
                                                <a href="controllers/CategoryController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >CategoryController</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-CategoryModule-878dc34b35bce521bac3afa01fe378c5828f18d16fd2c53c122f442cd7ece2672d6824b975f57e99210d812dc6f178c451a3679c4b370ea04a6b86149d7d1acf"' : 'data-bs-target="#xs-injectables-links-module-CategoryModule-878dc34b35bce521bac3afa01fe378c5828f18d16fd2c53c122f442cd7ece2672d6824b975f57e99210d812dc6f178c451a3679c4b370ea04a6b86149d7d1acf"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-CategoryModule-878dc34b35bce521bac3afa01fe378c5828f18d16fd2c53c122f442cd7ece2672d6824b975f57e99210d812dc6f178c451a3679c4b370ea04a6b86149d7d1acf"' :
                                        'id="xs-injectables-links-module-CategoryModule-878dc34b35bce521bac3afa01fe378c5828f18d16fd2c53c122f442cd7ece2672d6824b975f57e99210d812dc6f178c451a3679c4b370ea04a6b86149d7d1acf"' }>
                                        <li class="link">
                                            <a href="injectables/CategoryService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >CategoryService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/ChatModule.html" data-type="entity-link" >ChatModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                            'data-bs-target="#controllers-links-module-ChatModule-2fd3ed9649d438c9e8ac51541b26c94369eb63d32c1cf55dfdc318e5184ef738e02564424821a2318e9059a258348a10a9b7b07493e911503065bd05e0f0acbd"' : 'data-bs-target="#xs-controllers-links-module-ChatModule-2fd3ed9649d438c9e8ac51541b26c94369eb63d32c1cf55dfdc318e5184ef738e02564424821a2318e9059a258348a10a9b7b07493e911503065bd05e0f0acbd"' }>
                                            <span class="icon ion-md-swap"></span>
                                            <span>Controllers</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="controllers-links-module-ChatModule-2fd3ed9649d438c9e8ac51541b26c94369eb63d32c1cf55dfdc318e5184ef738e02564424821a2318e9059a258348a10a9b7b07493e911503065bd05e0f0acbd"' :
                                            'id="xs-controllers-links-module-ChatModule-2fd3ed9649d438c9e8ac51541b26c94369eb63d32c1cf55dfdc318e5184ef738e02564424821a2318e9059a258348a10a9b7b07493e911503065bd05e0f0acbd"' }>
                                            <li class="link">
                                                <a href="controllers/ChatController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >ChatController</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-ChatModule-2fd3ed9649d438c9e8ac51541b26c94369eb63d32c1cf55dfdc318e5184ef738e02564424821a2318e9059a258348a10a9b7b07493e911503065bd05e0f0acbd"' : 'data-bs-target="#xs-injectables-links-module-ChatModule-2fd3ed9649d438c9e8ac51541b26c94369eb63d32c1cf55dfdc318e5184ef738e02564424821a2318e9059a258348a10a9b7b07493e911503065bd05e0f0acbd"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-ChatModule-2fd3ed9649d438c9e8ac51541b26c94369eb63d32c1cf55dfdc318e5184ef738e02564424821a2318e9059a258348a10a9b7b07493e911503065bd05e0f0acbd"' :
                                        'id="xs-injectables-links-module-ChatModule-2fd3ed9649d438c9e8ac51541b26c94369eb63d32c1cf55dfdc318e5184ef738e02564424821a2318e9059a258348a10a9b7b07493e911503065bd05e0f0acbd"' }>
                                        <li class="link">
                                            <a href="injectables/ChatGateway.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >ChatGateway</a>
                                        </li>
                                        <li class="link">
                                            <a href="injectables/ChatService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >ChatService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/DemandPredictionModule.html" data-type="entity-link" >DemandPredictionModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                            'data-bs-target="#controllers-links-module-DemandPredictionModule-2c4f837421b11a567424d06058e64ebe64fcd43e452c7ffed3a99bdb074401c8f1d26de6f5e34a3537e91c63260ac2594042c601e71aa4b2bb514432c0324ce3"' : 'data-bs-target="#xs-controllers-links-module-DemandPredictionModule-2c4f837421b11a567424d06058e64ebe64fcd43e452c7ffed3a99bdb074401c8f1d26de6f5e34a3537e91c63260ac2594042c601e71aa4b2bb514432c0324ce3"' }>
                                            <span class="icon ion-md-swap"></span>
                                            <span>Controllers</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="controllers-links-module-DemandPredictionModule-2c4f837421b11a567424d06058e64ebe64fcd43e452c7ffed3a99bdb074401c8f1d26de6f5e34a3537e91c63260ac2594042c601e71aa4b2bb514432c0324ce3"' :
                                            'id="xs-controllers-links-module-DemandPredictionModule-2c4f837421b11a567424d06058e64ebe64fcd43e452c7ffed3a99bdb074401c8f1d26de6f5e34a3537e91c63260ac2594042c601e71aa4b2bb514432c0324ce3"' }>
                                            <li class="link">
                                                <a href="controllers/DemandPredictionController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >DemandPredictionController</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-DemandPredictionModule-2c4f837421b11a567424d06058e64ebe64fcd43e452c7ffed3a99bdb074401c8f1d26de6f5e34a3537e91c63260ac2594042c601e71aa4b2bb514432c0324ce3"' : 'data-bs-target="#xs-injectables-links-module-DemandPredictionModule-2c4f837421b11a567424d06058e64ebe64fcd43e452c7ffed3a99bdb074401c8f1d26de6f5e34a3537e91c63260ac2594042c601e71aa4b2bb514432c0324ce3"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-DemandPredictionModule-2c4f837421b11a567424d06058e64ebe64fcd43e452c7ffed3a99bdb074401c8f1d26de6f5e34a3537e91c63260ac2594042c601e71aa4b2bb514432c0324ce3"' :
                                        'id="xs-injectables-links-module-DemandPredictionModule-2c4f837421b11a567424d06058e64ebe64fcd43e452c7ffed3a99bdb074401c8f1d26de6f5e34a3537e91c63260ac2594042c601e71aa4b2bb514432c0324ce3"' }>
                                        <li class="link">
                                            <a href="injectables/DemandPredictionService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >DemandPredictionService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/FileModule.html" data-type="entity-link" >FileModule</a>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-FileModule-fc0606fca314033ddb6c8a180efa08d811501899e2508c8516e39222e18522bc657ee50afbdfea08d465f036157b4c97e3b96e400b6e24ea76259228b8f05c08"' : 'data-bs-target="#xs-injectables-links-module-FileModule-fc0606fca314033ddb6c8a180efa08d811501899e2508c8516e39222e18522bc657ee50afbdfea08d465f036157b4c97e3b96e400b6e24ea76259228b8f05c08"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-FileModule-fc0606fca314033ddb6c8a180efa08d811501899e2508c8516e39222e18522bc657ee50afbdfea08d465f036157b4c97e3b96e400b6e24ea76259228b8f05c08"' :
                                        'id="xs-injectables-links-module-FileModule-fc0606fca314033ddb6c8a180efa08d811501899e2508c8516e39222e18522bc657ee50afbdfea08d465f036157b4c97e3b96e400b6e24ea76259228b8f05c08"' }>
                                        <li class="link">
                                            <a href="injectables/FileService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >FileService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/GroupPurchaseModule.html" data-type="entity-link" >GroupPurchaseModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                            'data-bs-target="#controllers-links-module-GroupPurchaseModule-0bf9d732752f17d7d2204dfc1c2c957f367a0c1b11093968b7d725893bc61037f8700fa7d642b000ed7be682676553fbc40fd9f7ee3fbfcf3bb18a095eb958d0"' : 'data-bs-target="#xs-controllers-links-module-GroupPurchaseModule-0bf9d732752f17d7d2204dfc1c2c957f367a0c1b11093968b7d725893bc61037f8700fa7d642b000ed7be682676553fbc40fd9f7ee3fbfcf3bb18a095eb958d0"' }>
                                            <span class="icon ion-md-swap"></span>
                                            <span>Controllers</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="controllers-links-module-GroupPurchaseModule-0bf9d732752f17d7d2204dfc1c2c957f367a0c1b11093968b7d725893bc61037f8700fa7d642b000ed7be682676553fbc40fd9f7ee3fbfcf3bb18a095eb958d0"' :
                                            'id="xs-controllers-links-module-GroupPurchaseModule-0bf9d732752f17d7d2204dfc1c2c957f367a0c1b11093968b7d725893bc61037f8700fa7d642b000ed7be682676553fbc40fd9f7ee3fbfcf3bb18a095eb958d0"' }>
                                            <li class="link">
                                                <a href="controllers/GroupPurchaseController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >GroupPurchaseController</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-GroupPurchaseModule-0bf9d732752f17d7d2204dfc1c2c957f367a0c1b11093968b7d725893bc61037f8700fa7d642b000ed7be682676553fbc40fd9f7ee3fbfcf3bb18a095eb958d0"' : 'data-bs-target="#xs-injectables-links-module-GroupPurchaseModule-0bf9d732752f17d7d2204dfc1c2c957f367a0c1b11093968b7d725893bc61037f8700fa7d642b000ed7be682676553fbc40fd9f7ee3fbfcf3bb18a095eb958d0"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-GroupPurchaseModule-0bf9d732752f17d7d2204dfc1c2c957f367a0c1b11093968b7d725893bc61037f8700fa7d642b000ed7be682676553fbc40fd9f7ee3fbfcf3bb18a095eb958d0"' :
                                        'id="xs-injectables-links-module-GroupPurchaseModule-0bf9d732752f17d7d2204dfc1c2c957f367a0c1b11093968b7d725893bc61037f8700fa7d642b000ed7be682676553fbc40fd9f7ee3fbfcf3bb18a095eb958d0"' }>
                                        <li class="link">
                                            <a href="injectables/GroupPurchaseCronService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >GroupPurchaseCronService</a>
                                        </li>
                                        <li class="link">
                                            <a href="injectables/GroupPurchaseService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >GroupPurchaseService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/InvoiceModule.html" data-type="entity-link" >InvoiceModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                            'data-bs-target="#controllers-links-module-InvoiceModule-ec8e01bdceb1752b3c3953efcdb6847de32a4ccb8548e114c6c26f3215003281ad8fec12b688c9a3fddbbdfed699c2e7b0ec1d1361a65cedcdad1caaa56283af"' : 'data-bs-target="#xs-controllers-links-module-InvoiceModule-ec8e01bdceb1752b3c3953efcdb6847de32a4ccb8548e114c6c26f3215003281ad8fec12b688c9a3fddbbdfed699c2e7b0ec1d1361a65cedcdad1caaa56283af"' }>
                                            <span class="icon ion-md-swap"></span>
                                            <span>Controllers</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="controllers-links-module-InvoiceModule-ec8e01bdceb1752b3c3953efcdb6847de32a4ccb8548e114c6c26f3215003281ad8fec12b688c9a3fddbbdfed699c2e7b0ec1d1361a65cedcdad1caaa56283af"' :
                                            'id="xs-controllers-links-module-InvoiceModule-ec8e01bdceb1752b3c3953efcdb6847de32a4ccb8548e114c6c26f3215003281ad8fec12b688c9a3fddbbdfed699c2e7b0ec1d1361a65cedcdad1caaa56283af"' }>
                                            <li class="link">
                                                <a href="controllers/InvoiceController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >InvoiceController</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-InvoiceModule-ec8e01bdceb1752b3c3953efcdb6847de32a4ccb8548e114c6c26f3215003281ad8fec12b688c9a3fddbbdfed699c2e7b0ec1d1361a65cedcdad1caaa56283af"' : 'data-bs-target="#xs-injectables-links-module-InvoiceModule-ec8e01bdceb1752b3c3953efcdb6847de32a4ccb8548e114c6c26f3215003281ad8fec12b688c9a3fddbbdfed699c2e7b0ec1d1361a65cedcdad1caaa56283af"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-InvoiceModule-ec8e01bdceb1752b3c3953efcdb6847de32a4ccb8548e114c6c26f3215003281ad8fec12b688c9a3fddbbdfed699c2e7b0ec1d1361a65cedcdad1caaa56283af"' :
                                        'id="xs-injectables-links-module-InvoiceModule-ec8e01bdceb1752b3c3953efcdb6847de32a4ccb8548e114c6c26f3215003281ad8fec12b688c9a3fddbbdfed699c2e7b0ec1d1361a65cedcdad1caaa56283af"' }>
                                        <li class="link">
                                            <a href="injectables/InvoiceService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >InvoiceService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/NotificationModule.html" data-type="entity-link" >NotificationModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                            'data-bs-target="#controllers-links-module-NotificationModule-262996772091ce3fd26c7f82e80356ab74b5d682dd0dd4477776d51e5b659b953f827ca8aa1a5eb95c678eebccc6d32880cecd0ca84c21cfe4bc15a2f6c9e275"' : 'data-bs-target="#xs-controllers-links-module-NotificationModule-262996772091ce3fd26c7f82e80356ab74b5d682dd0dd4477776d51e5b659b953f827ca8aa1a5eb95c678eebccc6d32880cecd0ca84c21cfe4bc15a2f6c9e275"' }>
                                            <span class="icon ion-md-swap"></span>
                                            <span>Controllers</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="controllers-links-module-NotificationModule-262996772091ce3fd26c7f82e80356ab74b5d682dd0dd4477776d51e5b659b953f827ca8aa1a5eb95c678eebccc6d32880cecd0ca84c21cfe4bc15a2f6c9e275"' :
                                            'id="xs-controllers-links-module-NotificationModule-262996772091ce3fd26c7f82e80356ab74b5d682dd0dd4477776d51e5b659b953f827ca8aa1a5eb95c678eebccc6d32880cecd0ca84c21cfe4bc15a2f6c9e275"' }>
                                            <li class="link">
                                                <a href="controllers/NotificationController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >NotificationController</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-NotificationModule-262996772091ce3fd26c7f82e80356ab74b5d682dd0dd4477776d51e5b659b953f827ca8aa1a5eb95c678eebccc6d32880cecd0ca84c21cfe4bc15a2f6c9e275"' : 'data-bs-target="#xs-injectables-links-module-NotificationModule-262996772091ce3fd26c7f82e80356ab74b5d682dd0dd4477776d51e5b659b953f827ca8aa1a5eb95c678eebccc6d32880cecd0ca84c21cfe4bc15a2f6c9e275"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-NotificationModule-262996772091ce3fd26c7f82e80356ab74b5d682dd0dd4477776d51e5b659b953f827ca8aa1a5eb95c678eebccc6d32880cecd0ca84c21cfe4bc15a2f6c9e275"' :
                                        'id="xs-injectables-links-module-NotificationModule-262996772091ce3fd26c7f82e80356ab74b5d682dd0dd4477776d51e5b659b953f827ca8aa1a5eb95c678eebccc6d32880cecd0ca84c21cfe4bc15a2f6c9e275"' }>
                                        <li class="link">
                                            <a href="injectables/NotificationService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >NotificationService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/OfferModule.html" data-type="entity-link" >OfferModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                            'data-bs-target="#controllers-links-module-OfferModule-cba905ee427f08d510d7180798671892abd503aeb5d92e5555da1fd8456a07f3c9196eb298c35494f2d1192b1af1cce7e96cbc3794f16df4d01701449fcd31a9"' : 'data-bs-target="#xs-controllers-links-module-OfferModule-cba905ee427f08d510d7180798671892abd503aeb5d92e5555da1fd8456a07f3c9196eb298c35494f2d1192b1af1cce7e96cbc3794f16df4d01701449fcd31a9"' }>
                                            <span class="icon ion-md-swap"></span>
                                            <span>Controllers</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="controllers-links-module-OfferModule-cba905ee427f08d510d7180798671892abd503aeb5d92e5555da1fd8456a07f3c9196eb298c35494f2d1192b1af1cce7e96cbc3794f16df4d01701449fcd31a9"' :
                                            'id="xs-controllers-links-module-OfferModule-cba905ee427f08d510d7180798671892abd503aeb5d92e5555da1fd8456a07f3c9196eb298c35494f2d1192b1af1cce7e96cbc3794f16df4d01701449fcd31a9"' }>
                                            <li class="link">
                                                <a href="controllers/OfferController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >OfferController</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-OfferModule-cba905ee427f08d510d7180798671892abd503aeb5d92e5555da1fd8456a07f3c9196eb298c35494f2d1192b1af1cce7e96cbc3794f16df4d01701449fcd31a9"' : 'data-bs-target="#xs-injectables-links-module-OfferModule-cba905ee427f08d510d7180798671892abd503aeb5d92e5555da1fd8456a07f3c9196eb298c35494f2d1192b1af1cce7e96cbc3794f16df4d01701449fcd31a9"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-OfferModule-cba905ee427f08d510d7180798671892abd503aeb5d92e5555da1fd8456a07f3c9196eb298c35494f2d1192b1af1cce7e96cbc3794f16df4d01701449fcd31a9"' :
                                        'id="xs-injectables-links-module-OfferModule-cba905ee427f08d510d7180798671892abd503aeb5d92e5555da1fd8456a07f3c9196eb298c35494f2d1192b1af1cce7e96cbc3794f16df4d01701449fcd31a9"' }>
                                        <li class="link">
                                            <a href="injectables/OfferService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >OfferService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/OrderModule.html" data-type="entity-link" >OrderModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                            'data-bs-target="#controllers-links-module-OrderModule-90b5d635e6f5acfe982e8646342aa0284856d1bf7209cb8bc88e20d03ffda4ea46d4de3baebef53be5e8ff4697e7365f6a5e0d613994a21bfa08f620bb918a2b"' : 'data-bs-target="#xs-controllers-links-module-OrderModule-90b5d635e6f5acfe982e8646342aa0284856d1bf7209cb8bc88e20d03ffda4ea46d4de3baebef53be5e8ff4697e7365f6a5e0d613994a21bfa08f620bb918a2b"' }>
                                            <span class="icon ion-md-swap"></span>
                                            <span>Controllers</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="controllers-links-module-OrderModule-90b5d635e6f5acfe982e8646342aa0284856d1bf7209cb8bc88e20d03ffda4ea46d4de3baebef53be5e8ff4697e7365f6a5e0d613994a21bfa08f620bb918a2b"' :
                                            'id="xs-controllers-links-module-OrderModule-90b5d635e6f5acfe982e8646342aa0284856d1bf7209cb8bc88e20d03ffda4ea46d4de3baebef53be5e8ff4697e7365f6a5e0d613994a21bfa08f620bb918a2b"' }>
                                            <li class="link">
                                                <a href="controllers/OrderController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >OrderController</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-OrderModule-90b5d635e6f5acfe982e8646342aa0284856d1bf7209cb8bc88e20d03ffda4ea46d4de3baebef53be5e8ff4697e7365f6a5e0d613994a21bfa08f620bb918a2b"' : 'data-bs-target="#xs-injectables-links-module-OrderModule-90b5d635e6f5acfe982e8646342aa0284856d1bf7209cb8bc88e20d03ffda4ea46d4de3baebef53be5e8ff4697e7365f6a5e0d613994a21bfa08f620bb918a2b"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-OrderModule-90b5d635e6f5acfe982e8646342aa0284856d1bf7209cb8bc88e20d03ffda4ea46d4de3baebef53be5e8ff4697e7365f6a5e0d613994a21bfa08f620bb918a2b"' :
                                        'id="xs-injectables-links-module-OrderModule-90b5d635e6f5acfe982e8646342aa0284856d1bf7209cb8bc88e20d03ffda4ea46d4de3baebef53be5e8ff4697e7365f6a5e0d613994a21bfa08f620bb918a2b"' }>
                                        <li class="link">
                                            <a href="injectables/OrderService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >OrderService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/PrismaModule.html" data-type="entity-link" >PrismaModule</a>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-PrismaModule-d5acf8074fb2092225589b77c7962aad759425c6bcbce1c422d3e361fb478aa7d171c42009e150a2d0a72b7601d50ec4f542658de19543976743930ecb2c6c41"' : 'data-bs-target="#xs-injectables-links-module-PrismaModule-d5acf8074fb2092225589b77c7962aad759425c6bcbce1c422d3e361fb478aa7d171c42009e150a2d0a72b7601d50ec4f542658de19543976743930ecb2c6c41"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-PrismaModule-d5acf8074fb2092225589b77c7962aad759425c6bcbce1c422d3e361fb478aa7d171c42009e150a2d0a72b7601d50ec4f542658de19543976743930ecb2c6c41"' :
                                        'id="xs-injectables-links-module-PrismaModule-d5acf8074fb2092225589b77c7962aad759425c6bcbce1c422d3e361fb478aa7d171c42009e150a2d0a72b7601d50ec4f542658de19543976743930ecb2c6c41"' }>
                                        <li class="link">
                                            <a href="injectables/PrismaService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >PrismaService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/ProductModule.html" data-type="entity-link" >ProductModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                            'data-bs-target="#controllers-links-module-ProductModule-df290b0770edbc7a4e8ec1a805ecbf49f9dc10158a2e10b190b5b4893ac24688fc050a1b2e0b76e208b857e6ed275313b2828cbc1980bcb4a37eab7f1bbf1d2b"' : 'data-bs-target="#xs-controllers-links-module-ProductModule-df290b0770edbc7a4e8ec1a805ecbf49f9dc10158a2e10b190b5b4893ac24688fc050a1b2e0b76e208b857e6ed275313b2828cbc1980bcb4a37eab7f1bbf1d2b"' }>
                                            <span class="icon ion-md-swap"></span>
                                            <span>Controllers</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="controllers-links-module-ProductModule-df290b0770edbc7a4e8ec1a805ecbf49f9dc10158a2e10b190b5b4893ac24688fc050a1b2e0b76e208b857e6ed275313b2828cbc1980bcb4a37eab7f1bbf1d2b"' :
                                            'id="xs-controllers-links-module-ProductModule-df290b0770edbc7a4e8ec1a805ecbf49f9dc10158a2e10b190b5b4893ac24688fc050a1b2e0b76e208b857e6ed275313b2828cbc1980bcb4a37eab7f1bbf1d2b"' }>
                                            <li class="link">
                                                <a href="controllers/ProductController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >ProductController</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-ProductModule-df290b0770edbc7a4e8ec1a805ecbf49f9dc10158a2e10b190b5b4893ac24688fc050a1b2e0b76e208b857e6ed275313b2828cbc1980bcb4a37eab7f1bbf1d2b"' : 'data-bs-target="#xs-injectables-links-module-ProductModule-df290b0770edbc7a4e8ec1a805ecbf49f9dc10158a2e10b190b5b4893ac24688fc050a1b2e0b76e208b857e6ed275313b2828cbc1980bcb4a37eab7f1bbf1d2b"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-ProductModule-df290b0770edbc7a4e8ec1a805ecbf49f9dc10158a2e10b190b5b4893ac24688fc050a1b2e0b76e208b857e6ed275313b2828cbc1980bcb4a37eab7f1bbf1d2b"' :
                                        'id="xs-injectables-links-module-ProductModule-df290b0770edbc7a4e8ec1a805ecbf49f9dc10158a2e10b190b5b4893ac24688fc050a1b2e0b76e208b857e6ed275313b2828cbc1980bcb4a37eab7f1bbf1d2b"' }>
                                        <li class="link">
                                            <a href="injectables/ProductService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >ProductService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/ReviewModule.html" data-type="entity-link" >ReviewModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                            'data-bs-target="#controllers-links-module-ReviewModule-880fabeaf1c0ea04daaaa89bbc9fd3985a7eb3afd49e96e7827698bcfb61e6f106bf8ed6ecd4f6bb61d0ee595c62a0dd0e48cebf28cf535fb9eb3fc03b7c8e6f"' : 'data-bs-target="#xs-controllers-links-module-ReviewModule-880fabeaf1c0ea04daaaa89bbc9fd3985a7eb3afd49e96e7827698bcfb61e6f106bf8ed6ecd4f6bb61d0ee595c62a0dd0e48cebf28cf535fb9eb3fc03b7c8e6f"' }>
                                            <span class="icon ion-md-swap"></span>
                                            <span>Controllers</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="controllers-links-module-ReviewModule-880fabeaf1c0ea04daaaa89bbc9fd3985a7eb3afd49e96e7827698bcfb61e6f106bf8ed6ecd4f6bb61d0ee595c62a0dd0e48cebf28cf535fb9eb3fc03b7c8e6f"' :
                                            'id="xs-controllers-links-module-ReviewModule-880fabeaf1c0ea04daaaa89bbc9fd3985a7eb3afd49e96e7827698bcfb61e6f106bf8ed6ecd4f6bb61d0ee595c62a0dd0e48cebf28cf535fb9eb3fc03b7c8e6f"' }>
                                            <li class="link">
                                                <a href="controllers/ReviewController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >ReviewController</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-ReviewModule-880fabeaf1c0ea04daaaa89bbc9fd3985a7eb3afd49e96e7827698bcfb61e6f106bf8ed6ecd4f6bb61d0ee595c62a0dd0e48cebf28cf535fb9eb3fc03b7c8e6f"' : 'data-bs-target="#xs-injectables-links-module-ReviewModule-880fabeaf1c0ea04daaaa89bbc9fd3985a7eb3afd49e96e7827698bcfb61e6f106bf8ed6ecd4f6bb61d0ee595c62a0dd0e48cebf28cf535fb9eb3fc03b7c8e6f"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-ReviewModule-880fabeaf1c0ea04daaaa89bbc9fd3985a7eb3afd49e96e7827698bcfb61e6f106bf8ed6ecd4f6bb61d0ee595c62a0dd0e48cebf28cf535fb9eb3fc03b7c8e6f"' :
                                        'id="xs-injectables-links-module-ReviewModule-880fabeaf1c0ea04daaaa89bbc9fd3985a7eb3afd49e96e7827698bcfb61e6f106bf8ed6ecd4f6bb61d0ee595c62a0dd0e48cebf28cf535fb9eb3fc03b7c8e6f"' }>
                                        <li class="link">
                                            <a href="injectables/ReviewService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >ReviewService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/SearchModule.html" data-type="entity-link" >SearchModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                            'data-bs-target="#controllers-links-module-SearchModule-e58549296a34a25a73ee43f7685bad95dd9701d285c5bcef1b0920eeaea570adacf268c69f16d8d06c05f0ea629cfcd6586fa425faa393dd5e969bf99c2be7a6"' : 'data-bs-target="#xs-controllers-links-module-SearchModule-e58549296a34a25a73ee43f7685bad95dd9701d285c5bcef1b0920eeaea570adacf268c69f16d8d06c05f0ea629cfcd6586fa425faa393dd5e969bf99c2be7a6"' }>
                                            <span class="icon ion-md-swap"></span>
                                            <span>Controllers</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="controllers-links-module-SearchModule-e58549296a34a25a73ee43f7685bad95dd9701d285c5bcef1b0920eeaea570adacf268c69f16d8d06c05f0ea629cfcd6586fa425faa393dd5e969bf99c2be7a6"' :
                                            'id="xs-controllers-links-module-SearchModule-e58549296a34a25a73ee43f7685bad95dd9701d285c5bcef1b0920eeaea570adacf268c69f16d8d06c05f0ea629cfcd6586fa425faa393dd5e969bf99c2be7a6"' }>
                                            <li class="link">
                                                <a href="controllers/SearchController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >SearchController</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-SearchModule-e58549296a34a25a73ee43f7685bad95dd9701d285c5bcef1b0920eeaea570adacf268c69f16d8d06c05f0ea629cfcd6586fa425faa393dd5e969bf99c2be7a6"' : 'data-bs-target="#xs-injectables-links-module-SearchModule-e58549296a34a25a73ee43f7685bad95dd9701d285c5bcef1b0920eeaea570adacf268c69f16d8d06c05f0ea629cfcd6586fa425faa393dd5e969bf99c2be7a6"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-SearchModule-e58549296a34a25a73ee43f7685bad95dd9701d285c5bcef1b0920eeaea570adacf268c69f16d8d06c05f0ea629cfcd6586fa425faa393dd5e969bf99c2be7a6"' :
                                        'id="xs-injectables-links-module-SearchModule-e58549296a34a25a73ee43f7685bad95dd9701d285c5bcef1b0920eeaea570adacf268c69f16d8d06c05f0ea629cfcd6586fa425faa393dd5e969bf99c2be7a6"' }>
                                        <li class="link">
                                            <a href="injectables/SearchService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >SearchService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/ServiceModule.html" data-type="entity-link" >ServiceModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                            'data-bs-target="#controllers-links-module-ServiceModule-0f90267bbf209ce3ae7fdee3ffd5849bce6adbe4748876ba1d275371d0bc25695f9e8f7f99d4db61671436f635ebdae6d0c8a5fc6cb1f31f988e4721de8d37db"' : 'data-bs-target="#xs-controllers-links-module-ServiceModule-0f90267bbf209ce3ae7fdee3ffd5849bce6adbe4748876ba1d275371d0bc25695f9e8f7f99d4db61671436f635ebdae6d0c8a5fc6cb1f31f988e4721de8d37db"' }>
                                            <span class="icon ion-md-swap"></span>
                                            <span>Controllers</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="controllers-links-module-ServiceModule-0f90267bbf209ce3ae7fdee3ffd5849bce6adbe4748876ba1d275371d0bc25695f9e8f7f99d4db61671436f635ebdae6d0c8a5fc6cb1f31f988e4721de8d37db"' :
                                            'id="xs-controllers-links-module-ServiceModule-0f90267bbf209ce3ae7fdee3ffd5849bce6adbe4748876ba1d275371d0bc25695f9e8f7f99d4db61671436f635ebdae6d0c8a5fc6cb1f31f988e4721de8d37db"' }>
                                            <li class="link">
                                                <a href="controllers/ServiceController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >ServiceController</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-ServiceModule-0f90267bbf209ce3ae7fdee3ffd5849bce6adbe4748876ba1d275371d0bc25695f9e8f7f99d4db61671436f635ebdae6d0c8a5fc6cb1f31f988e4721de8d37db"' : 'data-bs-target="#xs-injectables-links-module-ServiceModule-0f90267bbf209ce3ae7fdee3ffd5849bce6adbe4748876ba1d275371d0bc25695f9e8f7f99d4db61671436f635ebdae6d0c8a5fc6cb1f31f988e4721de8d37db"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-ServiceModule-0f90267bbf209ce3ae7fdee3ffd5849bce6adbe4748876ba1d275371d0bc25695f9e8f7f99d4db61671436f635ebdae6d0c8a5fc6cb1f31f988e4721de8d37db"' :
                                        'id="xs-injectables-links-module-ServiceModule-0f90267bbf209ce3ae7fdee3ffd5849bce6adbe4748876ba1d275371d0bc25695f9e8f7f99d4db61671436f635ebdae6d0c8a5fc6cb1f31f988e4721de8d37db"' }>
                                        <li class="link">
                                            <a href="injectables/ServiceService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >ServiceService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/SmartSearchModule.html" data-type="entity-link" >SmartSearchModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                            'data-bs-target="#controllers-links-module-SmartSearchModule-3b8968118a0a81f5469d7782e125348b353b980362d4e7562ceafec0c3c00d9756ea00da079f7e1ef2aec2f53b38c3924b6c72387545414722b187c0cff01ec8"' : 'data-bs-target="#xs-controllers-links-module-SmartSearchModule-3b8968118a0a81f5469d7782e125348b353b980362d4e7562ceafec0c3c00d9756ea00da079f7e1ef2aec2f53b38c3924b6c72387545414722b187c0cff01ec8"' }>
                                            <span class="icon ion-md-swap"></span>
                                            <span>Controllers</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="controllers-links-module-SmartSearchModule-3b8968118a0a81f5469d7782e125348b353b980362d4e7562ceafec0c3c00d9756ea00da079f7e1ef2aec2f53b38c3924b6c72387545414722b187c0cff01ec8"' :
                                            'id="xs-controllers-links-module-SmartSearchModule-3b8968118a0a81f5469d7782e125348b353b980362d4e7562ceafec0c3c00d9756ea00da079f7e1ef2aec2f53b38c3924b6c72387545414722b187c0cff01ec8"' }>
                                            <li class="link">
                                                <a href="controllers/SmartSearchController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >SmartSearchController</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-SmartSearchModule-3b8968118a0a81f5469d7782e125348b353b980362d4e7562ceafec0c3c00d9756ea00da079f7e1ef2aec2f53b38c3924b6c72387545414722b187c0cff01ec8"' : 'data-bs-target="#xs-injectables-links-module-SmartSearchModule-3b8968118a0a81f5469d7782e125348b353b980362d4e7562ceafec0c3c00d9756ea00da079f7e1ef2aec2f53b38c3924b6c72387545414722b187c0cff01ec8"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-SmartSearchModule-3b8968118a0a81f5469d7782e125348b353b980362d4e7562ceafec0c3c00d9756ea00da079f7e1ef2aec2f53b38c3924b6c72387545414722b187c0cff01ec8"' :
                                        'id="xs-injectables-links-module-SmartSearchModule-3b8968118a0a81f5469d7782e125348b353b980362d4e7562ceafec0c3c00d9756ea00da079f7e1ef2aec2f53b38c3924b6c72387545414722b187c0cff01ec8"' }>
                                        <li class="link">
                                            <a href="injectables/SmartSearchService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >SmartSearchService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/SupplierModule.html" data-type="entity-link" >SupplierModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                            'data-bs-target="#controllers-links-module-SupplierModule-e28bbe7503605f7bb2e801e3bc12732314bdf8c12306d4ed2bf80b9afdff470be44b969cf76393a9c04a9ee39dba68b6240b1da1c0bd4258887f5fbbcfc677b5"' : 'data-bs-target="#xs-controllers-links-module-SupplierModule-e28bbe7503605f7bb2e801e3bc12732314bdf8c12306d4ed2bf80b9afdff470be44b969cf76393a9c04a9ee39dba68b6240b1da1c0bd4258887f5fbbcfc677b5"' }>
                                            <span class="icon ion-md-swap"></span>
                                            <span>Controllers</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="controllers-links-module-SupplierModule-e28bbe7503605f7bb2e801e3bc12732314bdf8c12306d4ed2bf80b9afdff470be44b969cf76393a9c04a9ee39dba68b6240b1da1c0bd4258887f5fbbcfc677b5"' :
                                            'id="xs-controllers-links-module-SupplierModule-e28bbe7503605f7bb2e801e3bc12732314bdf8c12306d4ed2bf80b9afdff470be44b969cf76393a9c04a9ee39dba68b6240b1da1c0bd4258887f5fbbcfc677b5"' }>
                                            <li class="link">
                                                <a href="controllers/SupplierController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >SupplierController</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-SupplierModule-e28bbe7503605f7bb2e801e3bc12732314bdf8c12306d4ed2bf80b9afdff470be44b969cf76393a9c04a9ee39dba68b6240b1da1c0bd4258887f5fbbcfc677b5"' : 'data-bs-target="#xs-injectables-links-module-SupplierModule-e28bbe7503605f7bb2e801e3bc12732314bdf8c12306d4ed2bf80b9afdff470be44b969cf76393a9c04a9ee39dba68b6240b1da1c0bd4258887f5fbbcfc677b5"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-SupplierModule-e28bbe7503605f7bb2e801e3bc12732314bdf8c12306d4ed2bf80b9afdff470be44b969cf76393a9c04a9ee39dba68b6240b1da1c0bd4258887f5fbbcfc677b5"' :
                                        'id="xs-injectables-links-module-SupplierModule-e28bbe7503605f7bb2e801e3bc12732314bdf8c12306d4ed2bf80b9afdff470be44b969cf76393a9c04a9ee39dba68b6240b1da1c0bd4258887f5fbbcfc677b5"' }>
                                        <li class="link">
                                            <a href="injectables/SupplierCronService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >SupplierCronService</a>
                                        </li>
                                        <li class="link">
                                            <a href="injectables/SupplierService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >SupplierService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/TapPaymentsModule.html" data-type="entity-link" >TapPaymentsModule</a>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-TapPaymentsModule-9e1b193be75dbb18edf4c60737539cb9cf9f5eed4e84d61141ef5856328fe42d6e1d7355778a0e851e69fbc65e216a2ce587bebcbcb4ae98ef193f82bf58469f"' : 'data-bs-target="#xs-injectables-links-module-TapPaymentsModule-9e1b193be75dbb18edf4c60737539cb9cf9f5eed4e84d61141ef5856328fe42d6e1d7355778a0e851e69fbc65e216a2ce587bebcbcb4ae98ef193f82bf58469f"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-TapPaymentsModule-9e1b193be75dbb18edf4c60737539cb9cf9f5eed4e84d61141ef5856328fe42d6e1d7355778a0e851e69fbc65e216a2ce587bebcbcb4ae98ef193f82bf58469f"' :
                                        'id="xs-injectables-links-module-TapPaymentsModule-9e1b193be75dbb18edf4c60737539cb9cf9f5eed4e84d61141ef5856328fe42d6e1d7355778a0e851e69fbc65e216a2ce587bebcbcb4ae98ef193f82bf58469f"' }>
                                        <li class="link">
                                            <a href="injectables/TapPaymentsService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >TapPaymentsService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/TranslationModule.html" data-type="entity-link" >TranslationModule</a>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-TranslationModule-a6708907c681a7146e617a4ab7eb581f9ba037b3a20fb83a53741f592be8bccf29167e210ae4a4bbc2337927aeeff6b5c4b78e3426418179991a9afb0862044a"' : 'data-bs-target="#xs-injectables-links-module-TranslationModule-a6708907c681a7146e617a4ab7eb581f9ba037b3a20fb83a53741f592be8bccf29167e210ae4a4bbc2337927aeeff6b5c4b78e3426418179991a9afb0862044a"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-TranslationModule-a6708907c681a7146e617a4ab7eb581f9ba037b3a20fb83a53741f592be8bccf29167e210ae4a4bbc2337927aeeff6b5c4b78e3426418179991a9afb0862044a"' :
                                        'id="xs-injectables-links-module-TranslationModule-a6708907c681a7146e617a4ab7eb581f9ba037b3a20fb83a53741f592be8bccf29167e210ae4a4bbc2337927aeeff6b5c4b78e3426418179991a9afb0862044a"' }>
                                        <li class="link">
                                            <a href="injectables/TranslationService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >TranslationService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/UserModule.html" data-type="entity-link" >UserModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                            'data-bs-target="#controllers-links-module-UserModule-ad79d3d5bd0db184bb2e25eea54ca91d882ae3d4f7a096c359ba49061d03ecca2598c954f27d8464cb31a598404bc51e3c3e639463df69407e3fcdfb72e51cc2"' : 'data-bs-target="#xs-controllers-links-module-UserModule-ad79d3d5bd0db184bb2e25eea54ca91d882ae3d4f7a096c359ba49061d03ecca2598c954f27d8464cb31a598404bc51e3c3e639463df69407e3fcdfb72e51cc2"' }>
                                            <span class="icon ion-md-swap"></span>
                                            <span>Controllers</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="controllers-links-module-UserModule-ad79d3d5bd0db184bb2e25eea54ca91d882ae3d4f7a096c359ba49061d03ecca2598c954f27d8464cb31a598404bc51e3c3e639463df69407e3fcdfb72e51cc2"' :
                                            'id="xs-controllers-links-module-UserModule-ad79d3d5bd0db184bb2e25eea54ca91d882ae3d4f7a096c359ba49061d03ecca2598c954f27d8464cb31a598404bc51e3c3e639463df69407e3fcdfb72e51cc2"' }>
                                            <li class="link">
                                                <a href="controllers/UserController.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >UserController</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-UserModule-ad79d3d5bd0db184bb2e25eea54ca91d882ae3d4f7a096c359ba49061d03ecca2598c954f27d8464cb31a598404bc51e3c3e639463df69407e3fcdfb72e51cc2"' : 'data-bs-target="#xs-injectables-links-module-UserModule-ad79d3d5bd0db184bb2e25eea54ca91d882ae3d4f7a096c359ba49061d03ecca2598c954f27d8464cb31a598404bc51e3c3e639463df69407e3fcdfb72e51cc2"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-UserModule-ad79d3d5bd0db184bb2e25eea54ca91d882ae3d4f7a096c359ba49061d03ecca2598c954f27d8464cb31a598404bc51e3c3e639463df69407e3fcdfb72e51cc2"' :
                                        'id="xs-injectables-links-module-UserModule-ad79d3d5bd0db184bb2e25eea54ca91d882ae3d4f7a096c359ba49061d03ecca2598c954f27d8464cb31a598404bc51e3c3e639463df69407e3fcdfb72e51cc2"' }>
                                        <li class="link">
                                            <a href="injectables/UserService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >UserService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/WathqModule.html" data-type="entity-link" >WathqModule</a>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ?
                                        'data-bs-target="#injectables-links-module-WathqModule-944469e4d72720ac5cb4e88a44322e62b55b23830812e8b3dd26d66082382aa52d30d9ba2e57d9f26cd4109de9910bae8fbadd8de589b228d15e615cda4cad21"' : 'data-bs-target="#xs-injectables-links-module-WathqModule-944469e4d72720ac5cb4e88a44322e62b55b23830812e8b3dd26d66082382aa52d30d9ba2e57d9f26cd4109de9910bae8fbadd8de589b228d15e615cda4cad21"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-WathqModule-944469e4d72720ac5cb4e88a44322e62b55b23830812e8b3dd26d66082382aa52d30d9ba2e57d9f26cd4109de9910bae8fbadd8de589b228d15e615cda4cad21"' :
                                        'id="xs-injectables-links-module-WathqModule-944469e4d72720ac5cb4e88a44322e62b55b23830812e8b3dd26d66082382aa52d30d9ba2e57d9f26cd4109de9910bae8fbadd8de589b228d15e615cda4cad21"' }>
                                        <li class="link">
                                            <a href="injectables/WathqService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >WathqService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                </ul>
                </li>
                    <li class="chapter">
                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ? 'data-bs-target="#classes-links"' :
                            'data-bs-target="#xs-classes-links"' }>
                            <span class="icon ion-ios-paper"></span>
                            <span>Classes</span>
                            <span class="icon ion-ios-arrow-down"></span>
                        </div>
                        <ul class="links collapse " ${ isNormalMode ? 'id="classes-links"' : 'id="xs-classes-links"' }>
                            <li class="link">
                                <a href="classes/AddCartItemDto.html" data-type="entity-link" >AddCartItemDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/AllExceptionsFilter.html" data-type="entity-link" >AllExceptionsFilter</a>
                            </li>
                            <li class="link">
                                <a href="classes/AnalyticsResponseDTO.html" data-type="entity-link" >AnalyticsResponseDTO</a>
                            </li>
                            <li class="link">
                                <a href="classes/BidResponseDto.html" data-type="entity-link" >BidResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/BuyerResponseDto.html" data-type="entity-link" >BuyerResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/CardDetailsDto.html" data-type="entity-link" >CardDetailsDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/CartBySupplierResponseDto.html" data-type="entity-link" >CartBySupplierResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/CartItemResponseDto.html" data-type="entity-link" >CartItemResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/CartResponseDto.html" data-type="entity-link" >CartResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/CategoryResponseDto.html" data-type="entity-link" >CategoryResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/ChangePasswordDto.html" data-type="entity-link" >ChangePasswordDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/ChatResponseDto.html" data-type="entity-link" >ChatResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/CheckoutCartDto.html" data-type="entity-link" >CheckoutCartDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/CheckoutRedirectDto.html" data-type="entity-link" >CheckoutRedirectDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/CreateBidDto.html" data-type="entity-link" >CreateBidDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/CreateCardStep1Dto.html" data-type="entity-link" >CreateCardStep1Dto</a>
                            </li>
                            <li class="link">
                                <a href="classes/CreateCardStep2Dto.html" data-type="entity-link" >CreateCardStep2Dto</a>
                            </li>
                            <li class="link">
                                <a href="classes/CreateInvoiceDto.html" data-type="entity-link" >CreateInvoiceDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/CreateInvoiceItemDto.html" data-type="entity-link" >CreateInvoiceItemDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/CreateItemReviewDto.html" data-type="entity-link" >CreateItemReviewDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/CreateOfferDto.html" data-type="entity-link" >CreateOfferDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/CreateProductDto.html" data-type="entity-link" >CreateProductDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/CreateReviewDto.html" data-type="entity-link" >CreateReviewDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/CreateServiceDto.html" data-type="entity-link" >CreateServiceDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/DemandPredictionResponseDto.html" data-type="entity-link" >DemandPredictionResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/EitherProductOrServiceConstraint.html" data-type="entity-link" >EitherProductOrServiceConstraint</a>
                            </li>
                            <li class="link">
                                <a href="classes/EmailDto.html" data-type="entity-link" >EmailDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/ForecastMonthDto.html" data-type="entity-link" >ForecastMonthDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/GroupPurchaseBuyerResponseDto.html" data-type="entity-link" >GroupPurchaseBuyerResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/GroupPurchaseResponseDto.html" data-type="entity-link" >GroupPurchaseResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/InactiveSupplierResponseDto.html" data-type="entity-link" >InactiveSupplierResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/InvoiceItemResponseDto.html" data-type="entity-link" >InvoiceItemResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/InvoiceResponseDto.html" data-type="entity-link" >InvoiceResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/IsEmailOrCrnConstraint.html" data-type="entity-link" >IsEmailOrCrnConstraint</a>
                            </li>
                            <li class="link">
                                <a href="classes/ItemReviewResponseDto.html" data-type="entity-link" >ItemReviewResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/LoginDto.html" data-type="entity-link" >LoginDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/MarkMessageAsReadDto.html" data-type="entity-link" >MarkMessageAsReadDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/MarkNotificationsAsReadDto.html" data-type="entity-link" >MarkNotificationsAsReadDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/MessageResponseDto.html" data-type="entity-link" >MessageResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/NotificationResponseDto.html" data-type="entity-link" >NotificationResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/OfferResponseDto.html" data-type="entity-link" >OfferResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/OrderItemResponseDto.html" data-type="entity-link" >OrderItemResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/OrderResponseDto.html" data-type="entity-link" >OrderResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/OverallReviewsResponseDTO.html" data-type="entity-link" >OverallReviewsResponseDTO</a>
                            </li>
                            <li class="link">
                                <a href="classes/PayInvoiceDto.html" data-type="entity-link" >PayInvoiceDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/PreInvoiceResponseDto.html" data-type="entity-link" >PreInvoiceResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/ProductResponseDto.html" data-type="entity-link" >ProductResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/ResetPasswordDto.html" data-type="entity-link" >ResetPasswordDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/RevenueByMonthResponseDTO.html" data-type="entity-link" >RevenueByMonthResponseDTO</a>
                            </li>
                            <li class="link">
                                <a href="classes/ReviewResponseDto.html" data-type="entity-link" >ReviewResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/ReviewsResponseDTO.html" data-type="entity-link" >ReviewsResponseDTO</a>
                            </li>
                            <li class="link">
                                <a href="classes/SendMessageDto.html" data-type="entity-link" >SendMessageDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/ServiceResponseDto.html" data-type="entity-link" >ServiceResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/SignupDto.html" data-type="entity-link" >SignupDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/SmartSearchRequestDto.html" data-type="entity-link" >SmartSearchRequestDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/SmartSearchResponseDto.html" data-type="entity-link" >SmartSearchResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/StockGroupDto.html" data-type="entity-link" >StockGroupDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/StockLevelsResponseDto.html" data-type="entity-link" >StockLevelsResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/StockProductDto.html" data-type="entity-link" >StockProductDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/StorefrontResponseDto.html" data-type="entity-link" >StorefrontResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/SupplierResponseDto.html" data-type="entity-link" >SupplierResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/SupplierReviewResponseDto.html" data-type="entity-link" >SupplierReviewResponseDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/TopItemResponseDTO.html" data-type="entity-link" >TopItemResponseDTO</a>
                            </li>
                            <li class="link">
                                <a href="classes/TopItemsResponseDTO.html" data-type="entity-link" >TopItemsResponseDTO</a>
                            </li>
                            <li class="link">
                                <a href="classes/UpdateNotificationPreferencesDto.html" data-type="entity-link" >UpdateNotificationPreferencesDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/UpdateProductDto.html" data-type="entity-link" >UpdateProductDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/UpdateServiceDto.html" data-type="entity-link" >UpdateServiceDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/UpdateSupplierDto.html" data-type="entity-link" >UpdateSupplierDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/UpdateUserDto.html" data-type="entity-link" >UpdateUserDto</a>
                            </li>
                            <li class="link">
                                <a href="classes/UserResponseDTO.html" data-type="entity-link" >UserResponseDTO</a>
                            </li>
                            <li class="link">
                                <a href="classes/UserWithRelationsResponseDTO.html" data-type="entity-link" >UserWithRelationsResponseDTO</a>
                            </li>
                            <li class="link">
                                <a href="classes/WishlistItemResponseDto.html" data-type="entity-link" >WishlistItemResponseDto</a>
                            </li>
                        </ul>
                    </li>
                        <li class="chapter">
                            <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ? 'data-bs-target="#injectables-links"' :
                                'data-bs-target="#xs-injectables-links"' }>
                                <span class="icon ion-md-arrow-round-down"></span>
                                <span>Injectables</span>
                                <span class="icon ion-ios-arrow-down"></span>
                            </div>
                            <ul class="links collapse " ${ isNormalMode ? 'id="injectables-links"' : 'id="xs-injectables-links"' }>
                                <li class="link">
                                    <a href="injectables/LoggerMiddleware.html" data-type="entity-link" >LoggerMiddleware</a>
                                </li>
                                <li class="link">
                                    <a href="injectables/ParseCrnPipe.html" data-type="entity-link" >ParseCrnPipe</a>
                                </li>
                                <li class="link">
                                    <a href="injectables/ParseEmailPipe.html" data-type="entity-link" >ParseEmailPipe</a>
                                </li>
                            </ul>
                        </li>
                    <li class="chapter">
                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ? 'data-bs-target="#guards-links"' :
                            'data-bs-target="#xs-guards-links"' }>
                            <span class="icon ion-ios-lock"></span>
                            <span>Guards</span>
                            <span class="icon ion-ios-arrow-down"></span>
                        </div>
                        <ul class="links collapse " ${ isNormalMode ? 'id="guards-links"' : 'id="xs-guards-links"' }>
                            <li class="link">
                                <a href="guards/JwtAuthGuard.html" data-type="entity-link" >JwtAuthGuard</a>
                            </li>
                            <li class="link">
                                <a href="guards/RolesGuard.html" data-type="entity-link" >RolesGuard</a>
                            </li>
                            <li class="link">
                                <a href="guards/VerifiedGuard.html" data-type="entity-link" >VerifiedGuard</a>
                            </li>
                        </ul>
                    </li>
                    <li class="chapter">
                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ? 'data-bs-target="#interfaces-links"' :
                            'data-bs-target="#xs-interfaces-links"' }>
                            <span class="icon ion-md-information-circle-outline"></span>
                            <span>Interfaces</span>
                            <span class="icon ion-ios-arrow-down"></span>
                        </div>
                        <ul class="links collapse " ${ isNormalMode ? ' id="interfaces-links"' : 'id="xs-interfaces-links"' }>
                            <li class="link">
                                <a href="interfaces/CreateNotification.html" data-type="entity-link" >CreateNotification</a>
                            </li>
                            <li class="link">
                                <a href="interfaces/JwtPayload.html" data-type="entity-link" >JwtPayload</a>
                            </li>
                        </ul>
                    </li>
                    <li class="chapter">
                        <div class="simple menu-toggler" data-bs-toggle="collapse" ${ isNormalMode ? 'data-bs-target="#miscellaneous-links"'
                            : 'data-bs-target="#xs-miscellaneous-links"' }>
                            <span class="icon ion-ios-cube"></span>
                            <span>Miscellaneous</span>
                            <span class="icon ion-ios-arrow-down"></span>
                        </div>
                        <ul class="links collapse " ${ isNormalMode ? 'id="miscellaneous-links"' : 'id="xs-miscellaneous-links"' }>
                            <li class="link">
                                <a href="miscellaneous/enumerations.html" data-type="entity-link">Enums</a>
                            </li>
                            <li class="link">
                                <a href="miscellaneous/functions.html" data-type="entity-link">Functions</a>
                            </li>
                            <li class="link">
                                <a href="miscellaneous/variables.html" data-type="entity-link">Variables</a>
                            </li>
                        </ul>
                    </li>
                        <li class="chapter">
                            <a data-type="chapter-link" href="routes.html"><span class="icon ion-ios-git-branch"></span>Routes</a>
                        </li>
                    <li class="chapter">
                        <a data-type="chapter-link" href="coverage.html"><span class="icon ion-ios-stats"></span>Documentation coverage</a>
                    </li>
                    <li class="divider"></li>
                    <li class="copyright">
                        Documentation generated using <a href="https://compodoc.app/" target="_blank" rel="noopener noreferrer">
                            <img data-src="images/compodoc-vectorise.png" class="img-responsive" data-type="compodoc-logo">
                        </a>
                    </li>
            </ul>
        </nav>
        `);
        this.innerHTML = tp.strings;
    }
});