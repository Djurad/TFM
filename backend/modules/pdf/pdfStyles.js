const COLORS = {
  bg: '#0A0E17',
  panel: '#111827',
  panelSoft: '#111827',
  panelAlt: '#0F131C',
  border: '#1F2937',
  borderSoft: '#2D3A5E',
  text: '#E5E7EB',
  muted: '#9CA3AF',
  subtle: '#6B7280',
  white: '#FFFFFF',
  critical: '#FF0055',
  high: '#FF6B00',
  medium: '#FFB347',
  low: '#00FFD1',
  info: '#AEB8CB',
  cyan: '#00FFD1',
  cyanSoft: '#003C37',
  success: '#22C55E',
  warning: '#FFB347',
  error: '#FF0055'
};

const SEVERITY = {
  critical: { label: 'Critical', color: COLORS.critical },
  high: { label: 'High', color: COLORS.high },
  medium: { label: 'Medium', color: COLORS.medium },
  low: { label: 'Low', color: COLORS.low },
  info: { label: 'Info', color: COLORS.info }
};

const FONTS = {
  regular: 'Helvetica',
  bold: 'Helvetica-Bold',
  mono: 'Courier'
};

const PAGE = {
  margin: 36,
  top: 54,
  bottom: 52,
  contentWidth: 523
};

module.exports = {
  COLORS,
  SEVERITY,
  FONTS,
  PAGE
};
