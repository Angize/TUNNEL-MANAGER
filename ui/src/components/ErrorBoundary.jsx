import { Component } from 'react'
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
      <div className="card" role="alert">
        <b>{T('page_crash_t')}</b>
        <p className="muted" style={{ margin: '8px 0 12px' }}>
          {T('page_crash_s')}
        </p>
        <button type="button" className="ghost" onClick={() => this.setState({ failed: false })}>
          {T('net_retry')}
        </button>
      </div>
    )
  }
}
