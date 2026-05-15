/* eslint-disable*/
import React, {useEffect, useState} from 'react'
import styles from './index.module.scss'

export type IIcon = {}

export default function Icon(props: IIcon) {
  return (
    <div className={styles.page}>
      <div className={styles.wrap}>
        <img src={require('./assets/image_1.png')} className={styles.image} />
        <img src={require('./assets/image_2.png')} className={styles.image1} />
        <img src={require('./assets/image_3.png')} className={styles.image2} />
        <img src={require('./assets/image_4.png')} className={styles.image3} />
        <div className={styles.container}>
          <div className={styles.content}>
            <img
              src={require('./assets/image_5.png')}
              className={styles.image4}
            />
            <img
              src={require('./assets/image_6.png')}
              className={styles.image5}
            />
            <img
              src={require('./assets/image_7.png')}
              className={styles.image6}
            />
          </div>
        </div>
        <img src={require('./assets/image_8.png')} className={styles.image7} />
        <img src={require('./assets/image_9.png')} className={styles.image8} />
        <div className={styles.container1}>
          <div className={styles.content1}></div>
          <img
            src={require('./assets/image_10.png')}
            className={styles.image9}
          />
        </div>
      </div>
      <div className={styles.wrap1}>
        <img
          src={require('./assets/image_11.png')}
          className={styles.image10}
        />
        <img
          src={require('./assets/image_12.png')}
          className={styles.image11}
        />
        <img
          src={require('./assets/image_13.png')}
          className={styles.image12}
        />
        <img
          src={require('./assets/image_14.png')}
          className={styles.image13}
        />
        <img
          src={require('./assets/image_15.png')}
          className={styles.image14}
        />
        <img
          src={require('./assets/image_16.png')}
          className={styles.image15}
        />
        <img
          src={require('./assets/image_17.png')}
          className={styles.image16}
        />
        <img
          src={require('./assets/image_18.png')}
          className={styles.image17}
        />
      </div>
      <div className={styles.wrap2}>
        <img
          src={require('./assets/image_19.png')}
          className={styles.image18}
        />
        <img
          src={require('./assets/image_20.png')}
          className={styles.image19}
        />
        <img
          src={require('./assets/image_21.png')}
          className={styles.image20}
        />
        <div className={styles.container2}>
          <div className={styles.content2}>
            <div className={styles.main}>
              <img
                src={require('./assets/image_22.png')}
                className={styles.image22}
              />
              <img
                src={require('./assets/image_23.png')}
                className={styles.image21}
              />
            </div>
            <div className={styles.main1}>
              <img
                src={require('./assets/image_24.png')}
                className={styles.image24}
              />
              <img
                src={require('./assets/image_25.png')}
                className={styles.image23}
              />
            </div>
            <div className={styles.main2}>
              <img
                src={require('./assets/image_26.png')}
                className={styles.image27}
              />
              <img
                src={require('./assets/image_27.png')}
                className={styles.image26}
              />
              <img
                src={require('./assets/image_28.png')}
                className={styles.image25}
              />
            </div>
          </div>
        </div>
        <img
          src={require('./assets/image_29.png')}
          className={styles.image28}
        />
        <img
          src={require('./assets/image_30.png')}
          className={styles.image29}
        />
        <div className={styles.container3}>
          <div className={styles.image30}>
            <img
              src={require('./assets/image_32.png')}
              className={styles.image31}
            />
          </div>
        </div>
        <div className={styles.container4}>
          <div className={styles.content3}></div>
        </div>
      </div>
      <div className={styles.wrap3}>
        <div className={styles.container5}>
          <img
            src={require('./assets/image_33.png')}
            className={styles.image32}
          />
        </div>
        <img
          src={require('./assets/image_34.png')}
          className={styles.image33}
        />
        <img
          src={require('./assets/image_35.png')}
          className={styles.image34}
        />
        <img
          src={require('./assets/image_36.png')}
          className={styles.image35}
        />
        <img
          src={require('./assets/image_37.png')}
          className={styles.image36}
        />
        <img
          src={require('./assets/image_38.png')}
          className={styles.image37}
        />
        <img
          src={require('./assets/image_39.png')}
          className={styles.image38}
        />
        <img
          src={require('./assets/image_40.png')}
          className={styles.image39}
        />
      </div>
      <div className={styles.wrap4}>
        <img
          src={require('./assets/image_41.png')}
          className={styles.image40}
        />
        <img
          src={require('./assets/image_42.png')}
          className={styles.image41}
        />
        <img
          src={require('./assets/image_43.png')}
          className={styles.image42}
        />
        <img
          src={require('./assets/image_44.png')}
          className={styles.image43}
        />
        <img
          src={require('./assets/image_45.png')}
          className={styles.image44}
        />
        <img
          src={require('./assets/image_46.png')}
          className={styles.image45}
        />
        <div className={styles.container6}>
          <div className={styles.content4}></div>
          <img
            src={require('./assets/image_47.png')}
            className={styles.image46}
          />
        </div>
        <img
          src={require('./assets/image_48.png')}
          className={styles.image47}
        />
      </div>
      <div className={styles.wrap5}>
        <div className={styles.container7}>
          <img
            src={require('./assets/image_49.png')}
            className={styles.image48}
          />
        </div>
        <div className={styles.container8}>
          <div className={styles.content5}>
            <img
              src={require('./assets/image_50.png')}
              className={styles.image49}
            />
          </div>
        </div>
        <div className={styles.container9}>
          <img
            src={require('./assets/image_51.png')}
            className={styles.image50}
          />
        </div>
        <div className={styles.container10}>
          <img
            src={require('./assets/image_52.png')}
            className={styles.image51}
          />
          <img
            src={require('./assets/image_53.png')}
            className={styles.image52}
          />
          <div className={styles.content6}></div>
          <img
            src={require('./assets/image_54.png')}
            className={styles.image53}
          />
          <img
            src={require('./assets/image_55.png')}
            className={styles.image54}
          />
          <img
            src={require('./assets/image_56.png')}
            className={styles.image55}
          />
        </div>
        <img
          src={require('./assets/image_57.png')}
          className={styles.image56}
        />
        <img
          src={require('./assets/image_58.png')}
          className={styles.image57}
        />
        <img
          src={require('./assets/image_59.png')}
          className={styles.image58}
        />
        <img
          src={require('./assets/image_60.png')}
          className={styles.image59}
        />
      </div>
      <div className={styles.wrap6}>
        <img
          src={require('./assets/image_61.png')}
          className={styles.image60}
        />
        <div className={styles.container11}>
          <div className={styles.content7}></div>
          <div className={styles.content8}></div>
          <div className={styles.content9}></div>
        </div>
        <div className={styles.container12}>
          <div className={styles.content10}></div>
          <div className={styles.content11}></div>
          <div className={styles.content12}></div>
        </div>
        <div className={styles.container13}>
          <div className={styles.content13}></div>
          <div className={styles.content14}></div>
          <div className={styles.content15}></div>
        </div>
        <img
          src={require('./assets/image_62.png')}
          className={styles.image61}
        />
        <img
          src={require('./assets/image_63.png')}
          className={styles.image62}
        />
        <img
          src={require('./assets/image_64.png')}
          className={styles.image63}
        />
        <img
          src={require('./assets/image_65.png')}
          className={styles.image64}
        />
      </div>
      <div className={styles.wrap7}>
        <div className={styles.container14}>
          <div className={styles.content16}></div>
          <img
            src={require('./assets/image_66.png')}
            className={styles.image65}
          />
        </div>
        <img
          src={require('./assets/image_67.png')}
          className={styles.image66}
        />
        <img
          src={require('./assets/image_68.png')}
          className={styles.image67}
        />
        <img
          src={require('./assets/image_69.png')}
          className={styles.image68}
        />
        <img
          src={require('./assets/image_70.png')}
          className={styles.image69}
        />
        <img
          src={require('./assets/image_71.png')}
          className={styles.image70}
        />
        <div className={styles.container15}>
          <div className={styles.content19}></div>
          <div className={styles.content17}></div>
          <div className={styles.content18}></div>
        </div>
        <img
          src={require('./assets/image_72.png')}
          className={styles.image71}
        />
      </div>
      <div className={styles.wrap8}>
        <img
          src={require('./assets/image_73.png')}
          className={styles.image72}
        />
        <div className={styles.container16}>
          <div className={styles.main3}>
            <img
              src={require('./assets/image_74.png')}
              className={styles.image73}
            />
          </div>
        </div>
        <img
          src={require('./assets/image_75.png')}
          className={styles.image74}
        />
        <img
          src={require('./assets/image_76.png')}
          className={styles.image75}
        />
        <img
          src={require('./assets/image_77.png')}
          className={styles.image76}
        />
        <img
          src={require('./assets/image_78.png')}
          className={styles.image77}
        />
        <img
          src={require('./assets/image_79.png')}
          className={styles.image78}
        />
        <img
          src={require('./assets/image_80.png')}
          className={styles.image79}
        />
      </div>
      <div className={styles.wrap9}>
        <img
          src={require('./assets/image_81.png')}
          className={styles.image80}
        />
        <img
          src={require('./assets/image_82.png')}
          className={styles.image81}
        />
      </div>
    </div>
  )
}
