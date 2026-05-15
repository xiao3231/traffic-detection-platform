/* eslint-disable*/
import React, {useEffect, useState} from 'react'
import styles from './index.module.scss'

export type IGeneratedComponent = {}

export default function GeneratedComponent(props: IGeneratedComponent) {
  return (
    <div className={styles.page}>
      <div className={styles.wrap}>
        <div className={styles.container}>
          <img src={require('./assets/image_1.png')} className={styles.image} />
          <div className={styles.content}>
            <div className={styles.main}>
              <img
                src={require('./assets/image_2.png')}
                className={styles.image1}
              />
              <img
                src={require('./assets/image_3.png')}
                className={styles.image2}
              />
              <img
                src={require('./assets/image_4.png')}
                className={styles.image3}
              />
              <div className={styles.section}>
                <div className={styles.subSection}>
                  <div className={styles.block}></div>
                  <div className={styles.block1}></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div className={styles.wrap1}>
        <div className={styles.container1}>
          <div className={styles.content1}>
            <div className={styles.main1}>
              <div className={styles.section1}>
                <div className={styles.subSection1}>
                  <img
                    src={require('./assets/image_5.png')}
                    className={styles.image4}
                  />
                  <img
                    src={require('./assets/image_6.png')}
                    className={styles.image5}
                  />
                </div>
              </div>
              <div className={styles.section2}>
                <div className={styles.subSection2}>
                  <div className={styles.block2}>
                    <img
                      src={require('./assets/image_7.png')}
                      className={styles.image6}
                    />
                  </div>
                  <div className={styles.block3}>
                    <img
                      src={require('./assets/image_8.png')}
                      className={styles.image7}
                    />
                    <img
                      src={require('./assets/image_9.png')}
                      className={styles.image8}
                    />
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className={styles.content2}>
            <div className={styles.main2}>
              <img
                src={require('./assets/image_10.png')}
                className={styles.image9}
              />
              <div className={styles.section3}>
                <img
                  src={require('./assets/image_11.png')}
                  className={styles.image10}
                />
              </div>
            </div>
          </div>
          <div className={styles.content3}>
            <div className={styles.main3}>
              <img
                src={require('./assets/image_12.png')}
                className={styles.image11}
              />
              <div className={styles.section4}>
                <img
                  src={require('./assets/image_13.png')}
                  className={styles.image12}
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
