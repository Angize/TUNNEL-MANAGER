import { Component } from 'react'
import Icon from './Icon.jsx'
import { T } from '../i18n/fa.js'

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { failed: false }
  }

  static getDerivedStateFromError() {
    return { failed: true }
  }

  render() {
    if (!this.state.failed) return this.props.children
    return (
      <div className="card loadfail" role="alert">
        <span>
          <b>{T('page_crash_t')}</b>
          {' — ' + T('page_crash_s')}
        </span>
        <button type="button" className="ghost" onClick={() => this.setState({ failed: false })}>
          <Icon name="redo" />
          {T('net_retry')}
        </button>
      </div>
    )
  }
}
