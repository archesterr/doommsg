import { useEffect, useId, useRef, type ReactNode } from 'react';
import { useT } from '../../i18n';
import { useApp } from '../../state/store';
import { IconClose } from '../icons/Icons';

export function Logo({ size = 40 }: { size?: number }) {
  // useId output contains characters that are invalid in url(#...) refs.
  const id = 'lg' + useId().replace(/[^a-zA-Z0-9_-]/g, '');
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" aria-hidden="true" className="logo">
      <defs>
        <linearGradient id={`${id}g`} x1="6" y1="4" x2="42" y2="44" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="var(--ember-1)" />
          <stop offset="1" stopColor="var(--ember-2)" />
        </linearGradient>
      </defs>
      <path
        d="M24 3.5c9.6 0 17.5 7.6 17.5 17 0 9.3-7.9 16.9-17.5 16.9-2 0-4-.3-5.8-1L9 41.5l1.6-9.2A16.5 16.5 0 0 1 6.5 20.5C6.5 11.1 14.4 3.5 24 3.5Z"
        fill={`url(#${id}g)`}
      />
      <rect x="17" y="19.5" width="14" height="10.5" rx="2.6" fill="var(--logo-ink)" />
      <path d="M19.8 19.5v-2.3a4.2 4.2 0 0 1 8.4 0v2.3" stroke="var(--logo-ink)" strokeWidth="2.4" fill="none" />
      <circle cx="24" cy="24.6" r="1.7" fill={`url(#${id}g)`} />
    </svg>
  );
}

export function Avatar({ name, hue, size = 44 }: { name: string; hue: number; size?: number }) {
  const initial = (name.replace(/^@/, '')[0] ?? '?').toUpperCase();
  return (
    <div
      className="avatar"
      style={{ width: size, height: size, fontSize: size * 0.42, ['--h' as string]: hue }}
      aria-hidden="true"
    >
      {initial}
    </div>
  );
}

export function Switch({ checked, onChange, label, hint }: { checked: boolean; onChange: (v: boolean) => void; label: string; hint?: string }) {
  const id = useId();
  return (
    <label className="row switch-row" htmlFor={id}>
      <span className="row-text">
        <span className="row-label">{label}</span>
        {hint && <span className="row-hint">{hint}</span>}
      </span>
      <input id={id} type="checkbox" role="switch" className="switch" checked={checked} onChange={(e) => onChange(e.target.checked)} />
    </label>
  );
}

export function Segmented<T extends string | number>({
  value,
  options,
  onChange,
  label,
}: {
  value: T;
  options: { value: T; label: string }[];
  onChange: (v: T) => void;
  label: string;
}) {
  return (
    <div className="segmented" role="radiogroup" aria-label={label}>
      {options.map((o) => (
        <button
          key={String(o.value)}
          type="button"
          role="radio"
          aria-checked={o.value === value}
          className={o.value === value ? 'on' : ''}
          onClick={() => onChange(o.value)}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

/** Accessible modal dialog built on <dialog> (focus trap, Esc to close). */
export function Modal({
  open,
  onClose,
  title,
  children,
  className = '',
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  className?: string;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const t = useT();
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog
      ref={ref}
      className={`modal ${className}`}
      onClose={onClose}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      onClick={(e) => {
        if (e.target === ref.current) onClose();
      }}
      aria-label={title}
    >
      {open && (
        <div className="modal-body">
          <header className="modal-head">
            <h2>{title}</h2>
            <button className="icon-btn" onClick={onClose} aria-label={t('common.close')}>
              <IconClose />
            </button>
          </header>
          {children}
        </div>
      )}
    </dialog>
  );
}

export function Confirm({
  open,
  text,
  danger,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  text: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const t = useT();
  return (
    <Modal open={open} onClose={onCancel} title={t('common.confirm')} className="confirm">
      <p className="confirm-text">{text}</p>
      <div className="btn-row">
        <button className="btn ghost" onClick={onCancel}>
          {t('common.cancel')}
        </button>
        <button className={`btn ${danger ? 'danger' : 'primary'}`} onClick={onConfirm} autoFocus>
          {t('common.confirm')}
        </button>
      </div>
    </Modal>
  );
}

export function Toaster() {
  const toasts = useApp((s) => s.toasts);
  const t = useT();
  return (
    <div className="toaster" role="status" aria-live="polite">
      {toasts.map((x) => (
        <div key={x.id} className={`toast ${x.tone === 'error' ? 'error' : ''}`}>
          {t(x.text)}
        </div>
      ))}
    </div>
  );
}
