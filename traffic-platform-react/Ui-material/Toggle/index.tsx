/* eslint-disable*/
import React, {useEffect, useState} from 'react'
import styles from './index.module.scss'

export type IToggle = {}

export default function Toggle(props: IToggle) {
  return <img src={require('./assets/image_1.png')} className={styles.image} />
}
