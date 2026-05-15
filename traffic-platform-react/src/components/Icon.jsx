import icon1 from '../../Ui-material/Icon/assets/image_1.png'
import icon2 from '../../Ui-material/Icon/assets/image_2.png'
import icon3 from '../../Ui-material/Icon/assets/image_3.png'
import icon4 from '../../Ui-material/Icon/assets/image_4.png'
import icon5 from '../../Ui-material/Icon/assets/image_5.png'
import icon6 from '../../Ui-material/Icon/assets/image_6.png'
import icon7 from '../../Ui-material/Icon/assets/image_7.png'
import icon8 from '../../Ui-material/Icon/assets/image_8.png'
import icon14 from '../../Ui-material/Icon/assets/image_14.png'
import icon15 from '../../Ui-material/Icon/assets/image_15.png'
import icon16 from '../../Ui-material/Icon/assets/image_16.png'
import icon17 from '../../Ui-material/Icon/assets/image_17.png'
import icon33 from '../../Ui-material/Icon/assets/image_33.png'
import icon34 from '../../Ui-material/Icon/assets/image_34.png'
import icon35 from '../../Ui-material/Icon/assets/image_35.png'
import icon36 from '../../Ui-material/Icon/assets/image_36.png'
import icon40 from '../../Ui-material/Icon/assets/image_40.png'
import icon41 from '../../Ui-material/Icon/assets/image_41.png'
import icon42 from '../../Ui-material/Icon/assets/image_42.png'
import icon43 from '../../Ui-material/Icon/assets/image_43.png'
import icon46 from '../../Ui-material/Icon/assets/image_46.png'
import icon47 from '../../Ui-material/Icon/assets/image_47.png'
import icon51 from '../../Ui-material/Icon/assets/image_51.png'
import icon60 from '../../Ui-material/Icon/assets/image_60.png'
import icon61 from '../../Ui-material/Icon/assets/image_61.png'
import icon62 from '../../Ui-material/Icon/assets/image_62.png'
import icon70 from '../../Ui-material/Icon/assets/image_70.png'
import icon71 from '../../Ui-material/Icon/assets/image_71.png'
import icon72 from '../../Ui-material/Icon/assets/image_72.png'
import icon73 from '../../Ui-material/Icon/assets/image_73.png'
import icon74 from '../../Ui-material/Icon/assets/image_74.png'
import icon75 from '../../Ui-material/Icon/assets/image_75.png'
import icon76 from '../../Ui-material/Icon/assets/image_76.png'
import icon77 from '../../Ui-material/Icon/assets/image_77.png'
import icon78 from '../../Ui-material/Icon/assets/image_78.png'
import icon79 from '../../Ui-material/Icon/assets/image_79.png'

const icons = {
  icon1, icon2, icon3, icon4, icon5, icon6, icon7, icon8,
  icon14, icon15, icon16, icon17,
  icon33, icon34, icon35, icon36,
  icon40, icon41, icon42, icon43,
  icon46, icon47, icon51,
  icon60, icon61, icon62,
  icon70, icon71, icon72, icon73, icon74, icon75, icon76, icon77, icon78, icon79
}

const iconMap = {
  upload: 'icon5',
  uploadCloud: 'icon6',
  fileUpload: 'icon7',
  shield: 'icon33',
  shieldCheck: 'icon34',
  shieldWarning: 'icon35',
  safe: 'icon36',
  danger: 'icon14',
  warning: 'icon15',
  alert: 'icon16',
  error: 'icon17',
  loading: 'icon60',
  scan: 'icon61',
  refresh: 'icon62',
  tcp: 'icon40',
  udp: 'icon41',
  http: 'icon42',
  https: 'icon43',
  user: 'icon46',
  userCircle: 'icon47',
  avatar: 'icon51',
  file: 'icon1',
  filePcap: 'icon8',
  folder: 'icon2',
  trash: 'icon70',
  close: 'icon71',
  check: 'icon3',
  plus: 'icon4',
  chart: 'icon72',
  barChart: 'icon73',
  pieChart: 'icon74',
  settings: 'icon75',
  menu: 'icon76',
  home: 'icon77',
  history: 'icon78',
  info: 'icon79',
}

export default function Icon({ name, size = 24, className = '' }) {
  const iconKey = iconMap[name] || 'icon1'
  const src = icons[iconKey]
  
  return (
    <img 
      src={src} 
      alt={name}
      style={{ width: size, height: size }}
      className={className}
    />
  )
}
