/*
Copyright 2015 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import React from 'react';
import "xterm/dist/xterm.css";
import XTermCtrl from 'app/lib/term/terminal';
import { TermEventEnum } from 'app/lib/term/enums';
import TtyAddressResolver from 'app/lib/term/ttyAddressResolver';

export default class XTerm extends React.Component {

  onRef = ref => {
    this.containerRef = ref;
  };

  componentDidMount() {
    const { onSessionEnd, ttyParams, title } = this.props;
    const addressResolver = new TtyAddressResolver(ttyParams);
    this.terminal = new XTermCtrl({
      el: this.containerRef,
      addressResolver
    });

    this.terminal.open();
    this.terminal.tty.on(TermEventEnum.CLOSE, onSessionEnd);

    document.title = title;
  }

  componentWillUnmount() {
    this.terminal.destroy();
  }

  shouldComponentUpdate() {
    return false;
  }

  focus() {
    this.terminal.term.focus();
  }

  render() {
    return ( <div ref={this.onRef} /> );
  }
}