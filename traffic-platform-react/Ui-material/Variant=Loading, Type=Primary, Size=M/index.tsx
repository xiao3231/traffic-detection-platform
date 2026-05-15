/* eslint-disable*/
import React, {useEffect, useState} from 'react'
import styles from './index.module.scss'

export type IGeneratedComponent = {}

export default function GeneratedComponent(props: IGeneratedComponent) {
  return (
    <div className={styles.page}>
      <img src={require('./assets/image_1.png')} className={styles.image} />
      <img src={require('./assets/image_2.png')} className={styles.image1} />
      <img src={require('./assets/image_3.png')} className={styles.image2} />
    </div>
  )
}
